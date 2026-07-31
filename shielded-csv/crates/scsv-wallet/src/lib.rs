//! The Shielded CSV wallet: account and coin stores, transaction building
//! (init/finalize), the receive-side ancestry-DAG verifier, chain scanning with
//! reorg demotion, and issuer operations (mint, freeze, seize, rotate,
//! renounce).
//!
//! The receive verifier is the native half of protocol soundness; see
//! `spec/16-RECEIVER.md`. There is no seed-based recovery — the wallet directory
//! is the only backup (`spec/19-WALLET.md`).

// Implemented in M7 (with issuer/seizure pieces from M5/M6).
