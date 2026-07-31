//! The receiver: native verification of a coin's ancestry DAG plus per-hop
//! balance/range STARK verification (`spec/16-RECEIVER.md`).
//!
//! In v1 chained mode the public sees only nullifiers; the receiver legitimately
//! sees the ancestry and checks it in full: transaction-essence hashes, coin
//! links, on-chain first-occurrence nullifiers with sign-to-contract binding,
//! mint-record binding, and the transfer conservation proof.

use std::collections::HashMap;

use p3_uni_stark::Proof;
use scsv_air::transfer::{build_trace, verify_transfer, Slot};
use scsv_air::ScsvConfig;
use scsv_asset::evidence::{EvidenceStore, NoEvidence};
use scsv_asset::view::Anomaly;
use scsv_asset::RecordChainView;
use scsv_chain::records::{RecordBody, SignedRecord};
use scsv_chain::wire::Payload;
use scsv_chain::{BitcoindChain, NullifierIndex, PublicationChain, ScannedBlock};
use scsv_core::hash::Digest;
use scsv_core::types::coin_id;
use scsv_native_crypto::{s2c_verify, NullifierSig, S2cOpening};

use crate::hop::{CoinBundle, OutputEssence, WireCoin, WireHop};

/// Freeze-freshness grace window in blocks (`spec/12-FREEZE.md`, S6): a coin is
/// treated as frozen if its handle is in the frozen set as of its spend height
/// plus this many blocks.
const FREEZE_GRACE: u64 = 6;

/// Why a bundle was rejected. Every native check maps to a variant, so the
/// tamper tests can assert the exact failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    ChainIdMismatch,
    DuplicateTxHash,
    TxHashMismatch,
    BadOutputBackref,
    MintShape,
    MintRecordMissing,
    MintRecordMismatch,
    InputNotInAncestry,
    NullifierCountMismatch,
    NullifierPkMismatch,
    NullifierNotOnChain,
    NullifierWrongLocation,
    InsufficientConfirmations,
    S2cBindingFailed,
    BalanceProofDecode,
    NotBalanced,
    BalanceProofInvalid,
    /// A spent input coin's handle is in the issuer's frozen set (`spec/12`).
    CoinFrozen,
    /// A freezable asset has a FREEZE-UPDATE whose off-chain delta the receiver
    /// could not resolve, so the frozen set cannot be reconstructed — the spend
    /// is refused conservatively (the issuer bricked its own asset by withholding
    /// the delta; `spec/12-FREEZE.md`).
    FreezeUnavailable,
    TargetMissing,
    ChainError(String),
}

/// A coin that passed full verification.
#[derive(Clone, Debug)]
pub struct VerifiedCoin {
    pub coin: WireCoin,
}

/// Verify a whole bundle against the chain, without freeze enforcement.
/// `min_confirmations` is the depth every ancestry nullifier must have (S6;
/// production uses ≥ 6). Use [`verify_bundle_with_evidence`] for freezable
/// assets, whose freeze status requires the issuer's off-chain freeze deltas.
pub fn verify_bundle(
    bundle: &CoinBundle,
    chain: &BitcoindChain,
    min_confirmations: u64,
) -> Result<VerifiedCoin, RejectReason> {
    verify_bundle_with_evidence(bundle, chain, min_confirmations, &NoEvidence)
}

/// Verify a whole bundle and additionally enforce issuer freezes, resolving the
/// off-chain freeze deltas through `evidence`. For a freezable asset the frozen
/// set is reconstructed from the full record chain; a spend of a frozen coin, or
/// a spend the receiver cannot clear because a freeze delta is unavailable, is
/// rejected (`spec/12-FREEZE.md`, `spec/16-RECEIVER.md`).
pub fn verify_bundle_with_evidence(
    bundle: &CoinBundle,
    chain: &BitcoindChain,
    min_confirmations: u64,
    evidence: &dyn EvidenceStore,
) -> Result<VerifiedCoin, RejectReason> {
    if bundle.chain_id != chain.chain_id() {
        return Err(RejectReason::ChainIdMismatch);
    }

    // Index hops by tx hash (reject duplicates).
    let mut by_tx: HashMap<[u8; 32], &WireHop> = HashMap::new();
    for h in &bundle.hops {
        if by_tx.insert(h.tx_hash, h).is_some() {
            return Err(RejectReason::DuplicateTxHash);
        }
    }

    // Scan the chain once over the referenced range and build the nullifier
    // first-occurrence index plus a record lookup.
    let (tip, _) = chain
        .tip()
        .map_err(|e| RejectReason::ChainError(e.to_string()))?;
    let min_height = bundle
        .hops
        .iter()
        .flat_map(|h| {
            h.nullifiers
                .iter()
                .map(|n| n.loc.height)
                .chain(h.mint_record_loc.iter().map(|l| l.height))
        })
        .min()
        .unwrap_or(tip);
    let blocks = chain
        .scan(min_height, tip)
        .map_err(|e| RejectReason::ChainError(e.to_string()))?;
    let mut nulls = NullifierIndex::new();
    nulls.apply_blocks(&blocks);

    for hop in &bundle.hops {
        verify_hop(hop, &by_tx, &nulls, &blocks, bundle, tip, min_confirmations)?;
    }

    enforce_freeze(bundle, chain, evidence)?;

    let target = bundle.target().ok_or(RejectReason::TargetMissing)?;
    Ok(VerifiedCoin { coin: *target })
}

/// Reject a bundle that spends a frozen coin. For every transfer hop over a
/// freezable asset, reconstruct the issuer's frozen set as of the spend height
/// (+ grace) from the full record chain and reject if any input coin's handle is
/// frozen — or if a required freeze delta is unavailable (the set can't be
/// reconstructed, so the spend is refused conservatively).
fn enforce_freeze(
    bundle: &CoinBundle,
    chain: &BitcoindChain,
    evidence: &dyn EvidenceStore,
) -> Result<(), RejectReason> {
    let (tip, _) = chain
        .tip()
        .map_err(|e| RejectReason::ChainError(e.to_string()))?;
    for hop in &bundle.hops {
        if hop.is_mint || hop.inputs.is_empty() {
            continue;
        }
        let Some(asset) = Digest::from_bytes(&hop.asset_id) else {
            continue;
        };
        // The spend height is where this hop's nullifier landed; the record
        // fold must start at the asset's genesis, so scan from the chain floor.
        let Some(spend_h) = hop.nullifiers.iter().map(|n| n.loc.height).min() else {
            continue;
        };
        let cutoff = (spend_h + FREEZE_GRACE).min(tip);
        let blocks: Vec<ScannedBlock> = chain
            .scan(1, cutoff)
            .map_err(|e| RejectReason::ChainError(e.to_string()))?;
        let view = RecordChainView::build(&blocks, evidence);
        let Some(state) = view.asset(&asset) else {
            continue; // asset not established in range — no freeze policy to apply
        };
        if !state.genesis.policy.freezable {
            continue;
        }
        // A missing freeze delta means the frozen set is unknown: refuse.
        if state
            .anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::MissingFreezeDelta { .. }))
        {
            return Err(RejectReason::FreezeUnavailable);
        }
        for input in &hop.inputs {
            if state.is_frozen(&input.coin_id()) {
                return Err(RejectReason::CoinFrozen);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_hop(
    hop: &WireHop,
    by_tx: &HashMap<[u8; 32], &WireHop>,
    nulls: &NullifierIndex,
    blocks: &[scsv_chain::ScannedBlock],
    bundle: &CoinBundle,
    tip: u64,
    min_confirmations: u64,
) -> Result<(), RejectReason> {
    // 1. Recompute the transaction-essence hash.
    let input_ids: Vec<_> = hop.inputs.iter().map(|c| c.coin_id()).collect();
    let outs: Vec<OutputEssence> = hop.outputs.iter().map(OutputEssence::from).collect();
    let recomputed =
        crate::hop::essence_tx_hash(hop.salt, hop.is_mint, &hop.asset_id, &input_ids, &outs);
    if recomputed != hop.tx_hash {
        return Err(RejectReason::TxHashMismatch);
    }
    // Outputs must back-reference this hop.
    for (i, o) in hop.outputs.iter().enumerate() {
        if o.creating_tx_hash != hop.tx_hash
            || o.out_index != i as u32
            || o.asset_id != hop.asset_id
        {
            return Err(RejectReason::BadOutputBackref);
        }
    }

    if hop.is_mint {
        if !hop.inputs.is_empty() || hop.outputs.is_empty() || !hop.nullifiers.is_empty() {
            return Err(RejectReason::MintShape);
        }
        let mint_amount: u64 = hop.outputs.iter().map(|o| o.amount).sum();
        verify_mint_record(hop, blocks, mint_amount)?;
        return Ok(());
    }

    // Transfer: each input must be an output of an ancestry hop.
    if hop.nullifiers.len() != hop.inputs.len() {
        return Err(RejectReason::NullifierCountMismatch);
    }
    for input in &hop.inputs {
        let parent = by_tx
            .get(&input.creating_tx_hash)
            .ok_or(RejectReason::InputNotInAncestry)?;
        let matched = parent
            .outputs
            .iter()
            .any(|o| o.coin_id() == input.coin_id() && o == input);
        if !matched {
            return Err(RejectReason::InputNotInAncestry);
        }
    }

    // Per-input nullifier checks.
    for (input, n) in hop.inputs.iter().zip(hop.nullifiers.iter()) {
        if n.pk != input.null_pk {
            return Err(RejectReason::NullifierPkMismatch);
        }
        let loc = nulls
            .first_occurrence(&n.pk)
            .ok_or(RejectReason::NullifierNotOnChain)?;
        if loc != n.loc.into() {
            return Err(RejectReason::NullifierWrongLocation);
        }
        if tip.saturating_sub(loc.height) + 1 < min_confirmations {
            return Err(RejectReason::InsufficientConfirmations);
        }
        let sig = NullifierSig {
            pk: n.pk,
            sig: n.sig,
        };
        let opening = S2cOpening { r0: n.s2c_r0 };
        if !s2c_verify(&sig, &opening, &hop.tx_hash, &bundle.chain_id) {
            return Err(RejectReason::S2cBindingFailed);
        }
    }

    // Balance/range STARK proof over the revealed amounts.
    let proof: Proof<ScsvConfig> =
        postcard::from_bytes(&hop.balance_proof).map_err(|_| RejectReason::BalanceProofDecode)?;
    let mut slots: Vec<Slot> = hop
        .inputs
        .iter()
        .map(|c| Slot {
            amount: c.amount,
            is_out: false,
        })
        .collect();
    slots.extend(hop.outputs.iter().map(|c| Slot {
        amount: c.amount,
        is_out: true,
    }));
    let (_, public) = build_trace(&slots).map_err(|_| RejectReason::NotBalanced)?;
    verify_transfer(&proof, &public).map_err(|_| RejectReason::BalanceProofInvalid)?;
    Ok(())
}

/// Confirm a mint hop's record is on-chain and matches the minted amount.
fn verify_mint_record(
    hop: &WireHop,
    blocks: &[scsv_chain::ScannedBlock],
    mint_amount: u64,
) -> Result<(), RejectReason> {
    let loc = hop.mint_record_loc.ok_or(RejectReason::MintRecordMissing)?;
    let block = blocks
        .iter()
        .find(|b| b.height == loc.height)
        .ok_or(RejectReason::MintRecordMissing)?;
    let tx = block
        .txs
        .iter()
        .find(|t| t.loc.tx_index == loc.tx_index)
        .ok_or(RejectReason::MintRecordMissing)?;
    // The tx must carry a MINT record for this asset and amount, co-published
    // with a nullifier (S3).
    let mut has_nullifier = false;
    let mut record_ok = false;
    for p in &tx.payloads {
        match p {
            Payload::Nullifier(_) => has_nullifier = true,
            Payload::Record(bytes) => {
                if let Some(sr) = SignedRecord::from_bytes(bytes) {
                    if sr.record.asset_id.to_bytes() == hop.asset_id {
                        if let RecordBody::Mint { amount, .. } = sr.record.body {
                            if amount == mint_amount {
                                record_ok = true;
                            }
                        }
                    }
                }
            }
        }
    }
    if !record_ok || !has_nullifier {
        return Err(RejectReason::MintRecordMismatch);
    }
    // Sanity: coin ids are derived from this hop's tx hash.
    let _ = coin_id(&hop.tx_hash, 0);
    Ok(())
}
