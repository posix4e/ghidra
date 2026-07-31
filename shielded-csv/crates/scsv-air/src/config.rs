//! The single STARK configuration and proof profile (`spec/14-AIR-STATEMENT.md`).
//!
//! There is exactly one profile, with real FRI parameters — no reduced "test"
//! parameters exist anywhere. The recipe (TwoAdicFriPcs over a Poseidon2 Merkle
//! commitment, degree-4 BabyBear extension challenge field, DuplexChallenger)
//! mirrors the Plonky3 uni-stark reference config and keeps the whole verifier
//! Poseidon2-shaped for future recursion.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

pub type Val = BabyBear;
pub type Perm = Poseidon2BabyBear<16>;
pub type MmcsHash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type MmcsCompress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MmcsHash, MmcsCompress, 2, 8>;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type Dft = Radix2DitParallel<Val>;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type ScsvConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Real FRI parameters. Conjectured security ≈ `log_blowup * num_queries +
/// query_pow_bits` bits = `3 * 34 + 16 = 118`. These are used everywhere,
/// including tests.
pub const LOG_BLOWUP: usize = 3;
pub const NUM_QUERIES: usize = 34;
pub const QUERY_POW_BITS: usize = 16;

/// Build the (deterministic) STARK config. The permutation used for the FRI
/// Merkle commitments is the fixed default BabyBear Poseidon2 instance, so
/// proving and verifying are reproducible with no RNG seeding.
pub fn config() -> ScsvConfig {
    let perm = p3_baby_bear::default_babybear_poseidon2_16();
    let hash = MmcsHash::new(perm.clone());
    let compress = MmcsCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    ScsvConfig::new(pcs, challenger)
}
