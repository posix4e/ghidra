//! The hand-written AIR for the Shielded CSV transaction compliance predicate,
//! plus the STARK prove/verify wrappers (Plonky3 uni-stark, Poseidon2 over
//! BabyBear). A single unified table proves every transaction kind; see
//! `spec/14-AIR-STATEMENT.md` for the normative statement and public-input
//! schema.
//!
//! There is exactly one proof profile (real FRI parameters) — no reduced
//! "test" parameters exist anywhere.
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

// Implemented from M4 onward.
