//! Real end-to-end STARK proofs of the in-circuit Poseidon2 permutation, at
//! full FRI parameters. Proving knowledge of a preimage for a public digest —
//! the actual arithmetized protocol hash.

use p3_field::PrimeCharacteristicRing;
use scsv_air::poseidon2_air::{prove_permutation, verify_permutation, NUM_COLS};
use scsv_air::poseidon2_native::{permute, WIDTH};
use scsv_core::hash::Digest;
use scsv_core::F;

#[test]
fn permutation_preimage_proves_and_verifies() {
    let input: [F; WIDTH] = core::array::from_fn(|i| F::from_u32((i as u32 + 1) * 7));
    let (proof, digest) = prove_permutation(input);
    // The digest is exactly the native permutation output.
    assert_eq!(digest.0, {
        let out = permute(input);
        core::array::from_fn::<F, 8, _>(|i| out[i])
    });
    verify_permutation(&proof, &digest).expect("verify");
}

#[test]
fn wrong_digest_is_rejected() {
    let input: [F; WIDTH] = core::array::from_fn(|i| F::from_u32(i as u32 + 100));
    let (proof, mut digest) = prove_permutation(input);
    // Tamper with the claimed digest — the proof must not verify against it.
    digest.0[0] += F::ONE;
    assert!(
        verify_permutation(&proof, &digest).is_err(),
        "digest binding"
    );
}

#[test]
fn distinct_inputs_give_distinct_digests() {
    let a: [F; WIDTH] = core::array::from_fn(|i| F::from_u32(i as u32));
    let b: [F; WIDTH] = core::array::from_fn(|i| F::from_u32(i as u32 + 1));
    let (_, da) = prove_permutation(a);
    let (_, db) = prove_permutation(b);
    assert_ne!(da, db);
}

#[test]
fn tampered_trace_does_not_verify() {
    // Build a valid trace, corrupt one round's output column, and confirm the
    // constraints reject it (either the prover panics on unsatisfiable
    // constraints in debug, or the verifier rejects).
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};
    use scsv_air::config::config;
    use scsv_air::poseidon2_air::Poseidon2Air;
    use scsv_air::poseidon2_native::permute_trace;

    let input: [F; WIDTH] = core::array::from_fn(|i| F::from_u32(i as u32 + 3));
    // Reconstruct the single-row trace the prover would build.
    let t = permute_trace(input);
    let digest = Digest(core::array::from_fn(|i| t.output[i]));

    // Rebuild the flat row via the public API path: prove a valid one first.
    let (good, _) = prove_permutation(input);
    verify_permutation(&good, &digest).expect("baseline verify");

    // Now hand-build a tampered trace: flip one cell in the first internal
    // round output and expect rejection.
    let height = 4;
    let mut values = F::zero_vec(height * NUM_COLS);
    // Fill honestly using the same layout by proving path is not exposed, so
    // reconstruct minimally: use write-through of a known-bad single cell on an
    // otherwise valid repeated row. We obtain a valid row by re-deriving it.
    // (This mirrors prove_permutation's row construction.)
    let mut row = vec![F::ZERO; NUM_COLS];
    scsv_air::poseidon2_air::fill_row_for_test(input, &mut row);
    // Corrupt an interior column (not the input, not the bound output).
    row[WIDTH * 2 + 3] += F::ONE;
    for r in 0..height {
        values[r * NUM_COLS..(r + 1) * NUM_COLS].copy_from_slice(&row);
    }
    let cfg = config();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = prove(
            &cfg,
            &Poseidon2Air,
            RowMajorMatrix::new(values, NUM_COLS),
            &digest.0,
        );
        verify(&cfg, &Poseidon2Air, &proof, &digest.0)
    }));
    match result {
        Err(_) => {}
        Ok(Ok(())) => panic!("tampered permutation trace verified"),
        Ok(Err(_)) => {}
    }
}
