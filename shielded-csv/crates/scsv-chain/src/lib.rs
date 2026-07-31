//! The Bitcoin publication layer for Shielded CSV.
//!
//! `BitcoindChain` is the only implementation: it speaks JSON-RPC to a real
//! Bitcoin Core node and publishes nullifiers and asset records as OP_RETURN
//! outputs of real, wallet-funded transactions. There is no mock chain and no
//! fallback — absence of a node is a hard error. See `spec/07-CHAIN-EMBEDDING.md`.

// Implemented in M3.
