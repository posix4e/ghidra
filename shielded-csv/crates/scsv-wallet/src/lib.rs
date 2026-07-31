//! The Shielded CSV wallet: account and coin stores, transaction building
//! (init/finalize), the receive-side ancestry-DAG verifier, chain scanning with
//! reorg demotion, and issuer operations (mint, freeze, seize, rotate,
//! renounce).
//!
//! The receive verifier is the native half of protocol soundness; see
//! `spec/16-RECEIVER.md`. There is no seed-based recovery — the wallet directory
//! is the only backup (`spec/19-WALLET.md`).

pub mod account;
pub mod hop;
pub mod receive;
pub mod wallet;

pub use account::{Account, AddressSecret, ShareableAddress};
pub use hop::{CoinBundle, Loc, WireCoin, WireHop, WireNullifier};
pub use receive::{verify_bundle, verify_bundle_with_evidence, RejectReason, VerifiedCoin};
pub use wallet::{IssuerState, OwnedCoin, Wallet, WalletError};
