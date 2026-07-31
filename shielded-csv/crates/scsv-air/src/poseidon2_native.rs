//! A step-by-step re-implementation of the width-16 BabyBear Poseidon2
//! permutation that exposes every intermediate round state, so the AIR trace
//! builder and the AIR constraints can mirror it exactly.
//!
//! This is validated bit-for-bit against `p3_baby_bear`'s own
//! `default_babybear_poseidon2_16().permute(..)` on random inputs (see the
//! tests), so the arithmetization provably matches the hash used everywhere
//! else in the protocol. The round constants are p3's public constants; the
//! linear layers reproduce p3's `mds_light_permutation` (external) and the
//! BabyBear internal diagonal.

use p3_baby_bear::{
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_field::{Field, PrimeCharacteristicRing};

use scsv_core::F;

pub const WIDTH: usize = 16;
pub const EXT_ROUNDS_HALF: usize = 4;
pub const INT_ROUNDS: usize = 13;

/// The BabyBear internal-layer diagonal `V` such that the internal linear layer
/// maps `s -> sum(s) + V[i]·s[i]`. Computed from p3's definition:
/// `[-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8, -1/16, -1/2^27]`.
pub fn internal_diag() -> [F; WIDTH] {
    let inv = |k: u32| F::from_u32(k).inverse();
    [
        -F::from_u32(2),
        F::ONE,
        F::from_u32(2),
        inv(2),
        F::from_u32(3),
        F::from_u32(4),
        -inv(2),
        -F::from_u32(3),
        -F::from_u32(4),
        inv(1 << 8),
        inv(4),
        inv(8),
        inv(1 << 27),
        -inv(1 << 8),
        -inv(16),
        -inv(1 << 27),
    ]
}

/// The x^7 S-box (D = 7 for BabyBear).
#[inline]
pub fn sbox(x: F) -> F {
    let x3 = x * x * x;
    x3 * x3 * x
}

/// Apply p3's 4×4 external MDS matrix `[2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]`.
#[inline]
fn apply_mat4(x: &mut [F; 4]) {
    let t01 = x[0] + x[1];
    let t23 = x[2] + x[3];
    let t0123 = t01 + t23;
    let t01123 = t0123 + x[1];
    let t01233 = t0123 + x[3];
    x[3] = t01233 + x[0].double(); // 3*x0 + x1 + x2 + 2*x3
    x[1] = t01123 + x[2].double(); // x0 + 2*x1 + 3*x2 + x3
    x[0] = t01123 + t01; // 2*x0 + 3*x1 + x2 + x3
    x[2] = t01233 + t23; // x0 + x1 + 2*x2 + 3*x3
}

/// The external linear layer (p3's `mds_light_permutation` for width 16): apply
/// mat4 to each group of 4, then add the per-position sums across the groups.
pub fn external_linear(state: &mut [F; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let mut c: [F; 4] = chunk.try_into().unwrap();
        apply_mat4(&mut c);
        chunk.copy_from_slice(&c);
    }
    let sums: [F; 4] = core::array::from_fn(|k| (0..WIDTH).step_by(4).map(|j| state[j + k]).sum());
    for (i, elem) in state.iter_mut().enumerate() {
        *elem += sums[i % 4];
    }
}

/// The internal linear layer: `s -> sum(s) + V[i]·s[i]`.
pub fn internal_linear(state: &mut [F; WIDTH], diag: &[F; WIDTH]) {
    let sum: F = state.iter().copied().sum();
    for (s, d) in state.iter_mut().zip(diag.iter()) {
        *s = sum + *d * *s;
    }
}

/// Every intermediate value of one permutation, for the trace builder.
pub struct PermTrace {
    pub input: [F; WIDTH],
    /// State after the initial external linear layer.
    pub after_init_linear: [F; WIDTH],
    /// Per external-initial round: (x3 aux for all lanes, output state).
    pub ext_init: [([F; WIDTH], [F; WIDTH]); EXT_ROUNDS_HALF],
    /// Per internal round: (x3 aux for lane 0, output state).
    pub internal: [(F, [F; WIDTH]); INT_ROUNDS],
    /// Per external-final round: (x3 aux for all lanes, output state).
    pub ext_final: [([F; WIDTH], [F; WIDTH]); EXT_ROUNDS_HALF],
    pub output: [F; WIDTH],
}

/// Run the permutation, recording every intermediate value.
pub fn permute_trace(input: [F; WIDTH]) -> PermTrace {
    let diag = internal_diag();
    let mut state = input;
    external_linear(&mut state);
    let after_init_linear = state;

    let mut ext_init = core::array::from_fn(|_| ([F::ZERO; WIDTH], [F::ZERO; WIDTH]));
    for (r, slot) in ext_init.iter_mut().enumerate() {
        let mut x3 = [F::ZERO; WIDTH];
        for (i, s) in state.iter_mut().enumerate() {
            let t = *s + BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL[r][i];
            x3[i] = t * t * t;
            *s = x3[i] * x3[i] * t; // t^7
        }
        external_linear(&mut state);
        *slot = (x3, state);
    }

    let mut internal = [(F::ZERO, [F::ZERO; WIDTH]); INT_ROUNDS];
    for (r, slot) in internal.iter_mut().enumerate() {
        let t = state[0] + BABYBEAR_POSEIDON2_RC_16_INTERNAL[r];
        let x3 = t * t * t;
        state[0] = x3 * x3 * t;
        internal_linear(&mut state, &diag);
        *slot = (x3, state);
    }

    let mut ext_final = core::array::from_fn(|_| ([F::ZERO; WIDTH], [F::ZERO; WIDTH]));
    for (r, slot) in ext_final.iter_mut().enumerate() {
        let mut x3 = [F::ZERO; WIDTH];
        for (i, s) in state.iter_mut().enumerate() {
            let t = *s + BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL[r][i];
            x3[i] = t * t * t;
            *s = x3[i] * x3[i] * t;
        }
        external_linear(&mut state);
        *slot = (x3, state);
    }

    PermTrace {
        input,
        after_init_linear,
        ext_init,
        internal,
        ext_final,
        output: state,
    }
}

/// Convenience: the permutation output only.
pub fn permute(input: [F; WIDTH]) -> [F; WIDTH] {
    permute_trace(input).output
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::default_babybear_poseidon2_16;
    use p3_symmetric::Permutation;

    #[test]
    fn matches_native_permutation() {
        let perm = default_babybear_poseidon2_16();
        // Deterministic pseudo-random inputs (no rng: derive from a counter).
        for seed in 0u32..64 {
            let input: [F; WIDTH] = core::array::from_fn(|i| {
                F::from_u32(
                    seed.wrapping_mul(2_654_435_761)
                        .wrapping_add(i as u32 * 40_503),
                )
            });
            let mut native = input;
            perm.permute_mut(&mut native);
            let ours = permute(input);
            assert_eq!(ours, native, "mismatch at seed {seed}");
        }
    }

    #[test]
    fn trace_output_consistent() {
        let input: [F; WIDTH] = core::array::from_fn(|i| F::from_u32(i as u32 + 1));
        let t = permute_trace(input);
        assert_eq!(t.output, permute(input));
        assert_eq!(t.ext_final[EXT_ROUNDS_HALF - 1].1, t.output);
    }
}
