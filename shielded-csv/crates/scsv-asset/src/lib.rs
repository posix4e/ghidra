//! Asset issuance and supply auditing: the per-asset record chain view
//! (first-published-wins, reorg-rewindable), evidence-gated provable burns and
//! seizures, frozen-set maintenance, and the pure-chain-scan supply audit.
//!
//! See `spec/09-ISSUANCE.md`, `spec/10-PUBLIC-SUPPLY.md`, `spec/11-BURNS.md`,
//! `spec/12-FREEZE.md`, `spec/13-SEIZURE.md`, `spec/18-AUDIT.md`.

pub mod audit;
pub mod evidence;
pub mod view;

pub use audit::{audit_blocks, audit_supply, AssetReport};
pub use evidence::{BurnProof, EvidenceStore, FreezeDelta, MemoryEvidence, SeizeEvidence};
pub use view::{Anomaly, AssetState, RecordChainView, SupplyEvent};
