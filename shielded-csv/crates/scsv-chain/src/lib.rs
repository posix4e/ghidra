//! The Bitcoin publication layer for Shielded CSV.
//!
//! `BitcoindChain` is the only implementation: it speaks JSON-RPC to a real
//! Bitcoin Core node and publishes nullifiers and asset records as OP_RETURN
//! outputs of real, wallet-funded transactions. There is no mock chain and no
//! fallback — absence of a node is a hard error. See `spec/07-CHAIN-EMBEDDING.md`.

pub mod bitcoind;
pub mod index;
pub mod records;
pub mod rpc;
pub mod wire;

pub use bitcoind::{BitcoindChain, ChainError};
pub use index::{NullifierIndex, ScannedBlock, ScannedTx};
pub use records::{Record, RecordBody, RecordKind, SignedRecord};
pub use wire::Payload;

use scsv_core::types::ChainLoc;

/// The ordered publication layer abstraction (`spec/07-CHAIN-EMBEDDING.md`).
///
/// This trait exists so the wallet, asset, and demo layers can be written
/// against a single interface. `BitcoindChain` is the only implementation —
/// there is deliberately no in-memory mock.
pub trait PublicationChain {
    type Error: std::error::Error;

    /// Publish payloads as OP_RETURN outputs of ONE funded, confirmed-later
    /// Bitcoin transaction, returning its txid. Co-publication in one tx is
    /// required for mint/burn record + nullifier atomicity (S3).
    fn publish(&self, payloads: &[Payload]) -> Result<[u8; 32], Self::Error>;

    /// Current best-chain height and tip hash.
    fn tip(&self) -> Result<(u64, [u8; 32]), Self::Error>;

    /// Scan blocks in `[from_height, to_height]` inclusive, returning the SCSV
    /// payloads found, in chain order.
    fn scan(&self, from_height: u64, to_height: u64) -> Result<Vec<ScannedBlock>, Self::Error>;

    /// Locate a transaction by txid, if confirmed.
    fn locate(&self, txid: &[u8; 32]) -> Result<Option<ChainLoc>, Self::Error>;
}
