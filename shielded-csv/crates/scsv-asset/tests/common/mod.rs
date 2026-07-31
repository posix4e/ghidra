//! Shared test issuer: builds correctly linked, signed record chains for every
//! record kind, plus the off-chain evidence they reference.
//!
//! Included by multiple test binaries; not every helper is used by each, so
//! dead-code warnings are expected and allowed here.
#![allow(dead_code)]

use scsv_asset::evidence::{BurnProof, FreezeDelta, MemoryEvidence, SeizeEvidence};
use scsv_asset::view::canonical_frozen_tree;
use scsv_chain::index::{ScannedBlock, ScannedTx};
use scsv_chain::records::{Record, RecordBody, SignedRecord};
use scsv_chain::wire::Payload;
use scsv_core::hash::Digest;
use scsv_core::types::{ChainLoc, Genesis, Policy};
use scsv_native_crypto::{bip340_sign, NullifierKeypair, NullifierSig};
use std::collections::BTreeSet;

pub struct Issuer {
    pub kp: NullifierKeypair,
    pub genesis: Genesis,
    pub last_hash: Digest,
    pub seq: u64,
    pub supply: u64,
    pub frozen: BTreeSet<[u8; 32]>,
}

pub fn nullifier_pk(seed: u8) -> [u8; 32] {
    NullifierKeypair::from_seed(&[seed; 32]).unwrap().pk
}

pub fn nsig(pk: [u8; 32]) -> NullifierSig {
    NullifierSig { pk, sig: [0u8; 64] }
}

/// Build a one-transaction block at `height` carrying the given payloads.
pub fn block(height: u64, payloads: Vec<Payload>) -> ScannedBlock {
    ScannedBlock {
        height,
        hash: [height as u8; 32],
        txs: vec![ScannedTx {
            loc: ChainLoc {
                height,
                tx_index: 0,
            },
            txid: [height as u8; 32],
            payloads,
        }],
    }
}

impl Issuer {
    pub fn new(seed: u8, public_supply: bool, max_supply: u64) -> Self {
        let kp = NullifierKeypair::from_seed(&[seed; 32]).unwrap();
        let genesis = Genesis {
            version: 1,
            issuer_pk: kp.pk,
            mint_auth_key_hash: Digest::ZERO,
            policy: Policy {
                public_supply,
                freezable: true,
                max_supply,
                decimals: 6,
            },
            ticker: "USDS".into(),
            name: "Test Dollar".into(),
            uri: "https://issuer.example/scsv".into(),
            extended_metadata_hash: [3u8; 32],
        };
        let last_hash = Record::genesis(&genesis).record_hash();
        Issuer {
            kp,
            genesis,
            last_hash,
            seq: 0,
            supply: 0,
            frozen: BTreeSet::new(),
        }
    }

    pub fn asset_id(&self) -> Digest {
        self.genesis.asset_id()
    }

    pub fn sign(&self, rec: Record) -> SignedRecord {
        let sig = bip340_sign(&self.kp, &rec.signing_message());
        SignedRecord { record: rec, sig }
    }

    pub fn genesis_record(&self) -> SignedRecord {
        self.sign(Record::genesis(&self.genesis))
    }

    pub fn next(&mut self, body: RecordBody) -> Record {
        self.seq += 1;
        let rec = Record {
            asset_id: self.genesis.asset_id(),
            seq: self.seq,
            prev_record_hash: self.last_hash,
            body,
        };
        self.last_hash = rec.record_hash();
        rec
    }

    pub fn mint(&mut self, amount: u64, null_pk: [u8; 32]) -> SignedRecord {
        self.supply += amount;
        let cumulative_supply = self.supply;
        let rec = self.next(RecordBody::Mint {
            amount,
            cumulative_supply,
            nullifier_pk: null_pk,
        });
        self.sign(rec)
    }

    pub fn burn(
        &mut self,
        amount: u64,
        null_pk: [u8; 32],
        burn_proof_hash: [u8; 32],
    ) -> SignedRecord {
        self.supply -= amount;
        let cumulative_supply = self.supply;
        let rec = self.next(RecordBody::Burn {
            amount,
            cumulative_supply,
            nullifier_pk: null_pk,
            burn_proof_hash,
        });
        self.sign(rec)
    }

    /// Freeze/unfreeze handles: apply the delta locally, compute the canonical
    /// new root, store the delta in `evidence`, and emit a signed FREEZE-UPDATE.
    pub fn freeze_update(
        &mut self,
        add: &[Digest],
        remove: &[Digest],
        evidence: &mut MemoryEvidence,
    ) -> SignedRecord {
        for h in remove {
            self.frozen.remove(&h.to_bytes());
        }
        for h in add {
            self.frozen.insert(h.to_bytes());
        }
        let new_frozen_root = canonical_frozen_tree(&self.frozen).root();
        let delta = FreezeDelta {
            added: add.to_vec(),
            removed: remove.to_vec(),
        };
        let delta_hash = evidence.put_delta(&delta);
        let rec = self.next(RecordBody::FreezeUpdate {
            new_frozen_root,
            delta_hash,
        });
        self.sign(rec)
    }

    /// A FREEZE-UPDATE whose stated root is wrong (for the mismatch test).
    pub fn freeze_update_bad_root(
        &mut self,
        add: &[Digest],
        evidence: &mut MemoryEvidence,
    ) -> SignedRecord {
        for h in add {
            self.frozen.insert(h.to_bytes());
        }
        let delta = FreezeDelta {
            added: add.to_vec(),
            removed: vec![],
        };
        let delta_hash = evidence.put_delta(&delta);
        let rec = self.next(RecordBody::FreezeUpdate {
            new_frozen_root: Digest::ZERO, // deliberately wrong
            delta_hash,
        });
        self.sign(rec)
    }

    /// A FREEZE-UPDATE whose delta is NOT stored in the evidence store.
    pub fn freeze_update_missing_delta(&mut self, add: &[Digest]) -> SignedRecord {
        for h in add {
            self.frozen.insert(h.to_bytes());
        }
        let new_frozen_root = canonical_frozen_tree(&self.frozen).root();
        let delta = FreezeDelta {
            added: add.to_vec(),
            removed: vec![],
        };
        let rec = self.next(RecordBody::FreezeUpdate {
            new_frozen_root,
            delta_hash: delta.hash(),
        });
        self.sign(rec)
    }

    pub fn seize(
        &mut self,
        coin_id: Digest,
        amount: u64,
        evidence: &mut MemoryEvidence,
    ) -> SignedRecord {
        self.supply -= amount;
        let cumulative_supply = self.supply;
        let ev = SeizeEvidence {
            asset_id: self.genesis.asset_id(),
            amount,
            coin_id,
        };
        let evidence_pack_hash = evidence.put_seize(&ev);
        let rec = self.next(RecordBody::Seize {
            coin_id,
            amount,
            cumulative_supply,
            evidence_pack_hash,
        });
        self.sign(rec)
    }

    /// A SEIZE whose evidence is not stored.
    pub fn seize_no_evidence(&mut self, coin_id: Digest, amount: u64) -> SignedRecord {
        self.supply -= amount;
        let cumulative_supply = self.supply;
        let ev = SeizeEvidence {
            asset_id: self.genesis.asset_id(),
            amount,
            coin_id,
        };
        let rec = self.next(RecordBody::Seize {
            coin_id,
            amount,
            cumulative_supply,
            evidence_pack_hash: ev.hash(),
        });
        self.sign(rec)
    }
}

// A helper used by burn scenarios.
pub fn burn_proof(asset_id: Digest, amount: u64) -> BurnProof {
    BurnProof {
        asset_id,
        amount,
        coin_id: Digest::ZERO,
    }
}
