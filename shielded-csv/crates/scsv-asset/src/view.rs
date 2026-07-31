//! The per-asset record chain view: a pure fold over scanned blocks that
//! reconstructs each asset's audited state from the chain alone
//! (`spec/08-RECORDS.md`, `spec/18-AUDIT.md`).
//!
//! First-published-wins per `(assetId, seq)`, hash-linked, issuer-signed with
//! key rotation. Mints self-enforce; burns and seizures reduce audited supply
//! only when their off-chain evidence is available and valid, otherwise the
//! audit stays conservative-high. The fold is deterministic and
//! reorg-rewindable: rebuilding from a truncated block list yields the state as
//! of that height.

use std::collections::{BTreeSet, HashMap};

use scsv_chain::index::ScannedBlock;
use scsv_chain::records::{RecordBody, SignedRecord};
use scsv_chain::wire::Payload;
use scsv_core::hash::{Digest, Domain};
use scsv_core::imt::IndexedMerkleTree;
use scsv_core::types::{ChainLoc, Genesis, XOnlyBytes};

use crate::evidence::{BurnProof, EvidenceStore, FreezeDelta, SeizeEvidence};

/// A supply-affecting event, for the audit timeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupplyEvent {
    Genesis {
        loc: ChainLoc,
    },
    Mint {
        amount: u64,
        loc: ChainLoc,
    },
    /// `counted` is false when the burn's evidence was unavailable/invalid, so
    /// audited supply was not reduced (conservative-high).
    Burn {
        amount: u64,
        counted: bool,
        loc: ChainLoc,
    },
    Seize {
        coin_id: Digest,
        amount: u64,
        counted: bool,
        loc: ChainLoc,
    },
    RotateKey {
        loc: ChainLoc,
    },
    Renounce {
        loc: ChainLoc,
    },
    MetadataUpdate {
        loc: ChainLoc,
    },
    FreezeUpdate {
        root: Digest,
        loc: ChainLoc,
    },
}

/// A rejected or suspicious record, surfaced by the audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anomaly {
    /// A second record competing for an already-decided `(assetId, seq)`.
    Equivocation { seq: u64, loc: ChainLoc },
    /// A record out of sequence (gap) — cannot be applied.
    OutOfSequence {
        seq: u64,
        expected: u64,
        loc: ChainLoc,
    },
    /// `prev_record_hash` did not match the chain tip.
    BrokenLink { seq: u64, loc: ChainLoc },
    /// Signature invalid under the current issuer key.
    BadSignature { seq: u64, loc: ChainLoc },
    /// Mint/burn `cumulative_supply` arithmetic inconsistent.
    BadArithmetic { seq: u64, loc: ChainLoc },
    /// A mint would exceed `maxSupply`.
    MaxSupplyExceeded { seq: u64, loc: ChainLoc },
    /// A mint/burn record whose nullifier is not in the same chain transaction.
    MissingCoPublishedNullifier { seq: u64, loc: ChainLoc },
    /// A mint after the issuer renounced.
    MintAfterRenounce { seq: u64, loc: ChainLoc },
    /// Burn evidence unavailable/invalid — not counted (conservative-high).
    MissingBurnEvidence { seq: u64, loc: ChainLoc },
    /// Seize on a handle not currently in the frozen set.
    SeizeWithoutFreeze { seq: u64, loc: ChainLoc },
    /// Seize evidence unavailable/invalid — not counted.
    MissingSeizeEvidence { seq: u64, loc: ChainLoc },
    /// A freeze-update whose delta was unavailable (asset spendability bricked).
    MissingFreezeDelta { seq: u64, loc: ChainLoc },
    /// A freeze-update that would unfreeze a seized handle (rejected; monotone).
    UnfreezeOfSeized { seq: u64, loc: ChainLoc },
    /// A freeze-update whose applied delta did not reproduce the stated root.
    FreezeRootMismatch { seq: u64, loc: ChainLoc },
}

/// The audited state of one asset.
#[derive(Clone)]
pub struct AssetState {
    pub genesis: Genesis,
    pub asset_id: Digest,
    pub genesis_loc: ChainLoc,
    pub current_issuer_pk: XOnlyBytes,
    pub renounced: bool,
    pub last_seq: u64,
    pub last_record_hash: Digest,
    /// Supply as the issuer's records claim it (follows `cumulative_supply`).
    pub claimed_supply: u64,
    /// Supply the audit stands behind: mints counted; burns/seizes counted only
    /// with valid evidence. Always ≥ `claimed_supply`.
    pub audited_supply: u64,
    pub extended_metadata_hash: [u8; 32],
    /// The canonical frozen-handle set (source of truth for the frozen root).
    pub frozen_handles: BTreeSet<[u8; 32]>,
    /// `(height, root)` after each accepted freeze-update, for `frozen_root_at`.
    pub frozen_root_history: Vec<(u64, Digest)>,
    /// Handles that have been seized (monotone — never removed).
    pub seized: BTreeSet<[u8; 32]>,
    pub events: Vec<SupplyEvent>,
    pub anomalies: Vec<Anomaly>,
}

/// Build the canonical frozen tree for a handle set: a fresh indexed Merkle
/// tree with the handles inserted in ascending key order, so the root is a pure
/// function of the *set* (independent of the order handles were added on-chain).
/// Both the issuer and the auditor follow this rule, so their roots agree.
pub fn canonical_frozen_tree(handles: &BTreeSet<[u8; 32]>) -> IndexedMerkleTree {
    let mut digests: Vec<Digest> = handles.iter().filter_map(Digest::from_bytes).collect();
    digests.sort_by(|a, b| a.key_cmp(b));
    let mut tree = IndexedMerkleTree::new(Domain::FrozenLeaf);
    for d in digests {
        let _ = tree.insert(d);
    }
    tree
}

impl AssetState {
    fn new(genesis: Genesis, loc: ChainLoc, genesis_record_hash: Digest) -> Self {
        let empty_root = IndexedMerkleTree::new(Domain::FrozenLeaf).root();
        AssetState {
            asset_id: genesis.asset_id(),
            current_issuer_pk: genesis.issuer_pk,
            extended_metadata_hash: genesis.extended_metadata_hash,
            genesis,
            genesis_loc: loc,
            renounced: false,
            last_seq: 0,
            last_record_hash: genesis_record_hash,
            claimed_supply: 0,
            audited_supply: 0,
            frozen_handles: BTreeSet::new(),
            frozen_root_history: vec![(loc.height, empty_root)],
            seized: BTreeSet::new(),
            events: vec![SupplyEvent::Genesis { loc }],
            anomalies: Vec::new(),
        }
    }

    /// The current frozen root.
    pub fn frozen_root(&self) -> Digest {
        canonical_frozen_tree(&self.frozen_handles).root()
    }

    /// The frozen root in effect at `height` (the latest accepted at or below
    /// it). Used with the ±grace window by the receiver (`spec/12-FREEZE.md`).
    pub fn frozen_root_at(&self, height: u64) -> Digest {
        let mut root = self.frozen_root_history[0].1;
        for (h, r) in &self.frozen_root_history {
            if *h <= height {
                root = *r;
            } else {
                break;
            }
        }
        root
    }

    /// Whether `handle` is currently frozen.
    pub fn is_frozen(&self, handle: &Digest) -> bool {
        self.frozen_handles.contains(&handle.to_bytes())
    }
}

/// The fold over all assets.
#[derive(Clone, Default)]
pub struct RecordChainView {
    assets: HashMap<[u8; 32], AssetState>,
}

impl RecordChainView {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn asset(&self, asset_id: &Digest) -> Option<&AssetState> {
        self.assets.get(&asset_id.to_bytes())
    }

    pub fn assets(&self) -> impl Iterator<Item = &AssetState> {
        self.assets.values()
    }

    /// Build a view from scanned blocks in order, resolving evidence through
    /// `evidence`.
    pub fn build(blocks: &[ScannedBlock], evidence: &dyn EvidenceStore) -> Self {
        let mut view = Self::new();
        for block in blocks {
            view.apply_block(block, evidence);
        }
        view
    }

    /// Fold one block. Records within a transaction are processed in order; the
    /// transaction's nullifier public keys are available for the co-publication
    /// check (S3).
    pub fn apply_block(&mut self, block: &ScannedBlock, evidence: &dyn EvidenceStore) {
        for tx in &block.txs {
            // Nullifier pks co-published in this transaction.
            let tx_nullifiers: BTreeSet<[u8; 32]> = tx
                .payloads
                .iter()
                .filter_map(|p| match p {
                    Payload::Nullifier(n) => Some(n.pk),
                    _ => None,
                })
                .collect();
            for p in &tx.payloads {
                if let Payload::Record(bytes) = p {
                    if let Some(sr) = SignedRecord::from_bytes(bytes) {
                        self.apply_record(&sr, tx.loc, &tx_nullifiers, evidence);
                    }
                }
            }
        }
    }

    fn apply_record(
        &mut self,
        sr: &SignedRecord,
        loc: ChainLoc,
        tx_nullifiers: &BTreeSet<[u8; 32]>,
        evidence: &dyn EvidenceStore,
    ) {
        let rec = &sr.record;
        let key = rec.asset_id.to_bytes();

        // Genesis (seq 0) creates the asset; a second one is equivocation.
        if let RecordBody::Genesis(g) = &rec.body {
            if self.assets.contains_key(&key) {
                if let Some(a) = self.assets.get_mut(&key) {
                    a.anomalies.push(Anomaly::Equivocation { seq: 0, loc });
                }
                return;
            }
            // Genesis self-consistency was checked at decode; verify signature.
            if !sr.verify(&g.issuer_pk) {
                // No asset to attach the anomaly to yet; drop silently (an
                // unsigned genesis simply never creates an asset).
                return;
            }
            self.assets
                .insert(key, AssetState::new(g.clone(), loc, rec.record_hash()));
            return;
        }

        let Some(a) = self.assets.get_mut(&key) else {
            return; // record for an unknown asset
        };

        // Sequence and hash-link discipline (first-wins in chain order).
        if rec.seq <= a.last_seq {
            a.anomalies
                .push(Anomaly::Equivocation { seq: rec.seq, loc });
            return;
        }
        if rec.seq != a.last_seq + 1 {
            a.anomalies.push(Anomaly::OutOfSequence {
                seq: rec.seq,
                expected: a.last_seq + 1,
                loc,
            });
            return;
        }
        if rec.prev_record_hash != a.last_record_hash {
            a.anomalies.push(Anomaly::BrokenLink { seq: rec.seq, loc });
            return;
        }
        if !sr.verify(&a.current_issuer_pk) {
            a.anomalies
                .push(Anomaly::BadSignature { seq: rec.seq, loc });
            return;
        }

        let seq = rec.seq;
        match &rec.body {
            RecordBody::Genesis(_) => unreachable!("handled above"),
            RecordBody::Mint {
                amount,
                cumulative_supply,
                nullifier_pk,
            } => {
                if a.renounced {
                    a.anomalies.push(Anomaly::MintAfterRenounce { seq, loc });
                    return;
                }
                if !tx_nullifiers.contains(nullifier_pk) {
                    a.anomalies
                        .push(Anomaly::MissingCoPublishedNullifier { seq, loc });
                    return;
                }
                if *cumulative_supply != a.claimed_supply + amount {
                    a.anomalies.push(Anomaly::BadArithmetic { seq, loc });
                    return;
                }
                let max = a.genesis.policy.max_supply;
                if max != 0 && *cumulative_supply > max {
                    a.anomalies.push(Anomaly::MaxSupplyExceeded { seq, loc });
                    return;
                }
                a.claimed_supply = *cumulative_supply;
                a.audited_supply += amount;
                a.events.push(SupplyEvent::Mint {
                    amount: *amount,
                    loc,
                });
            }
            RecordBody::Burn {
                amount,
                cumulative_supply,
                nullifier_pk,
                burn_proof_hash,
            } => {
                if !tx_nullifiers.contains(nullifier_pk) {
                    a.anomalies
                        .push(Anomaly::MissingCoPublishedNullifier { seq, loc });
                    return;
                }
                if a.claimed_supply < *amount || *cumulative_supply != a.claimed_supply - amount {
                    a.anomalies.push(Anomaly::BadArithmetic { seq, loc });
                    return;
                }
                a.claimed_supply = *cumulative_supply;
                let counted = evidence
                    .get(burn_proof_hash)
                    .and_then(|b| BurnProof::from_bytes(&b))
                    .is_some_and(|p| p.asset_id == rec.asset_id && p.amount == *amount);
                if counted {
                    a.audited_supply = a.audited_supply.saturating_sub(*amount);
                } else {
                    a.anomalies.push(Anomaly::MissingBurnEvidence { seq, loc });
                }
                a.events.push(SupplyEvent::Burn {
                    amount: *amount,
                    counted,
                    loc,
                });
            }
            RecordBody::Seize {
                coin_id,
                amount,
                cumulative_supply,
                evidence_pack_hash,
            } => {
                if !a.frozen_handles.contains(&coin_id.to_bytes()) {
                    a.anomalies.push(Anomaly::SeizeWithoutFreeze { seq, loc });
                    return;
                }
                if a.claimed_supply < *amount || *cumulative_supply != a.claimed_supply - amount {
                    a.anomalies.push(Anomaly::BadArithmetic { seq, loc });
                    return;
                }
                a.claimed_supply = *cumulative_supply;
                a.seized.insert(coin_id.to_bytes());
                let counted = evidence
                    .get(evidence_pack_hash)
                    .and_then(|b| SeizeEvidence::from_bytes(&b))
                    .is_some_and(|e| e.asset_id == rec.asset_id && e.amount == *amount);
                if counted {
                    a.audited_supply = a.audited_supply.saturating_sub(*amount);
                } else {
                    a.anomalies.push(Anomaly::MissingSeizeEvidence { seq, loc });
                }
                a.events.push(SupplyEvent::Seize {
                    coin_id: *coin_id,
                    amount: *amount,
                    counted,
                    loc,
                });
            }
            RecordBody::RotateKey { new_issuer_pk } => {
                a.current_issuer_pk = *new_issuer_pk;
                a.events.push(SupplyEvent::RotateKey { loc });
            }
            RecordBody::Renounce => {
                a.renounced = true;
                a.events.push(SupplyEvent::Renounce { loc });
            }
            RecordBody::MetadataUpdate {
                new_extended_metadata_hash,
            } => {
                a.extended_metadata_hash = *new_extended_metadata_hash;
                a.events.push(SupplyEvent::MetadataUpdate { loc });
            }
            RecordBody::FreezeUpdate {
                new_frozen_root,
                delta_hash,
            } => {
                let Some(delta) = evidence
                    .get(delta_hash)
                    .and_then(|b| FreezeDelta::from_bytes(&b))
                else {
                    a.anomalies.push(Anomaly::MissingFreezeDelta { seq, loc });
                    return;
                };
                // Monotonicity: a seized handle can never be unfrozen.
                if delta
                    .removed
                    .iter()
                    .any(|h| a.seized.contains(&h.to_bytes()))
                {
                    a.anomalies.push(Anomaly::UnfreezeOfSeized { seq, loc });
                    return;
                }
                // Apply the delta to a trial set and check the canonical root.
                let mut trial = a.frozen_handles.clone();
                for h in &delta.removed {
                    trial.remove(&h.to_bytes());
                }
                for h in &delta.added {
                    trial.insert(h.to_bytes());
                }
                if canonical_frozen_tree(&trial).root() != *new_frozen_root {
                    a.anomalies.push(Anomaly::FreezeRootMismatch { seq, loc });
                    return;
                }
                a.frozen_handles = trial;
                a.frozen_root_history.push((loc.height, *new_frozen_root));
                a.events.push(SupplyEvent::FreezeUpdate {
                    root: *new_frozen_root,
                    loc,
                });
            }
        }

        a.last_seq = seq;
        a.last_record_hash = rec.record_hash();
    }
}
