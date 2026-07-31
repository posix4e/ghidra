//! Out-of-circuit secp256k1 for Shielded CSV: BIP340 Schnorr and the
//! sign-to-contract nullifier construction. These primitives are verified
//! natively by scanners and receivers and NEVER appear inside the AIR.
//!
//! See `spec/06-NULLIFIERS.md`.

pub mod bip340;

pub use bip340::{
    bip340_sign, bip340_verify, nullifier_message, s2c_sign, s2c_verify, tagged_hash,
    NullifierKeypair, NullifierSig, S2cOpening, XOnlyBytes,
};
