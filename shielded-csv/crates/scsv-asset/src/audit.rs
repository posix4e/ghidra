//! The supply audit: compute an asset's supply and history from the chain
//! alone (`spec/18-AUDIT.md`). A pure function of scanned records — no
//! cooperation from the issuer or any holder is needed.

use scsv_chain::{PublicationChain, ScannedBlock};
use scsv_core::hash::Digest;
use scsv_core::types::Policy;

use crate::evidence::EvidenceStore;
use crate::view::{Anomaly, AssetState, RecordChainView, SupplyEvent};

/// The audit result for one asset.
#[derive(Clone, Debug)]
pub struct AssetReport {
    pub asset_id: Digest,
    pub ticker: String,
    pub name: String,
    pub policy: Policy,
    /// Supply the audit stands behind (mints minus *proven* burns/seizes).
    /// Always ≥ `claimed_supply`.
    pub audited_supply: u64,
    /// Supply as the issuer's records claim it.
    pub claimed_supply: u64,
    /// True when every burn/seize was backed by valid evidence (audited ==
    /// claimed). False means the audit is conservative-high.
    pub fully_backed: bool,
    pub renounced: bool,
    pub frozen_count: usize,
    pub seized_count: usize,
    pub timeline: Vec<SupplyEvent>,
    pub anomalies: Vec<Anomaly>,
}

impl AssetReport {
    fn from_state(a: &AssetState) -> Self {
        AssetReport {
            asset_id: a.asset_id,
            ticker: a.genesis.ticker.clone(),
            name: a.genesis.name.clone(),
            policy: a.genesis.policy,
            audited_supply: a.audited_supply,
            claimed_supply: a.claimed_supply,
            fully_backed: a.audited_supply == a.claimed_supply,
            renounced: a.renounced,
            frozen_count: a.frozen_handles.len(),
            seized_count: a.seized.len(),
            timeline: a.events.clone(),
            anomalies: a.anomalies.clone(),
        }
    }
}

/// Build a report for every asset in a set of scanned blocks.
pub fn audit_blocks(blocks: &[ScannedBlock], evidence: &dyn EvidenceStore) -> Vec<AssetReport> {
    let view = RecordChainView::build(blocks, evidence);
    let mut reports: Vec<AssetReport> = view.assets().map(AssetReport::from_state).collect();
    reports.sort_by(|x, y| {
        x.ticker
            .cmp(&y.ticker)
            .then(x.asset_id.key_cmp(&y.asset_id))
    });
    reports
}

/// Scan a real chain over `[from_height, to_height]` and audit every asset.
/// `to_height` defaults to the chain tip when `None`.
pub fn audit_supply<C: PublicationChain>(
    chain: &C,
    evidence: &dyn EvidenceStore,
    from_height: u64,
    to_height: Option<u64>,
) -> Result<Vec<AssetReport>, C::Error> {
    let tip = match to_height {
        Some(h) => h,
        None => chain.tip()?.0,
    };
    let blocks = chain.scan(from_height, tip)?;
    Ok(audit_blocks(&blocks, evidence))
}
