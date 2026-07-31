//! Core types and primitives for Shielded CSV: the STARK field, digest/limb
//! codecs, the Poseidon2 hash instance, indexed Merkle trees, and the protocol
//! data types. This crate performs no I/O and never touches secp256k1.
//!
//! Everything downstream (the AIR, the chain layer, the wallet) shares the hash
//! and tree semantics defined here so that native and in-circuit computations
//! agree bit-for-bit. See `spec/01-CRYPTO.md`.

pub mod codec;
pub mod field;
pub mod hash;
pub mod imt;
pub mod types;

pub use field::F;
pub use hash::{Digest, Domain};
pub use types::{AccountState, ChainLoc, Coin, Genesis, Policy, TxHash, XOnlyBytes};
