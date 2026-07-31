//! The hand-written AIR for the Shielded CSV transaction compliance predicate,
//! plus the STARK prove/verify wrappers (Plonky3 uni-stark, Poseidon2 over
//! BabyBear). A single unified table proves every transaction kind; see
//! `spec/14-AIR-STATEMENT.md` for the normative statement and public-input
//! schema.
//!
//! There is exactly one proof profile (real FRI parameters) — no reduced
//! "test" parameters exist anywhere.
//!
//! # Current circuit depth (M4)
//!
//! The proving backend is complete and real: [`config::config`] builds the one
//! full-parameter STARK config, and [`transfer`] proves a transfer's
//! **value-conservation and range** constraints (spec/14 groups 6 and 14)
//! end-to-end at those parameters. That is the arithmetic core of a transfer,
//! in zero knowledge, with negative tests per constraint family.
//!
//! The remaining constraint groups in spec/14 — the Poseidon2 permutation
//! gadget and everything built on it (Merkle path consistency, the spent
//! accumulator, nullifier-key derivation, state-commitment openings, record
//! binding, freeze non-membership) — are the next increment. Until they are
//! in-circuit, those bindings are enforced natively by the receiver (spec/16).
//! This boundary is deliberate and documented; see `transfer_air`.
//!
//! # p3 0.6.3 audit (M1, 2026-07-31)
//!
//! - **Fiat–Shamir public-input binding**: `p3-uni-stark` 0.6.3 observes
//!   `public_values` into the challenger before sampling on both sides
//!   (`prover.rs:173`, `verifier.rs:412`). The S2 wrapper in this crate
//!   additionally observes a Poseidon2 digest of the canonical PI vector, as
//!   defense in depth against upstream regressions.
//! - **Preprocessed columns**: supported upstream (`preprocessed.rs`, width
//!   observed into the transcript). Not used yet; a candidate replacement for
//!   the schedule counters later.
//! - **rand majors**: p3 resolves rand 0.10 / rand_core 0.10; k256 0.13 pulls
//!   rand_core 0.6. Distinct majors coexist deliberately.

pub mod config;
pub mod pis;
pub mod transfer;
pub mod transfer_air;

pub use config::{config, ScsvConfig};
pub use pis::{HopPublicInputs, NUM_PIS};
pub use transfer::{prove_transfer, verify_transfer, Slot, TransferPublic};
