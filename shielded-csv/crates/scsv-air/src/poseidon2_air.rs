//! A hand-written AIR for the width-16 BabyBear Poseidon2 permutation, proving
//! knowledge of a preimage whose permutation output equals a public digest.
//!
//! This is the real in-circuit hash: the constraint system reproduces, round by
//! round, the exact permutation validated against p3 in `poseidon2_native`. The
//! linear layers are shared generic code (same arithmetic for witness values
//! `F` and constraint expressions `AB::Expr`), so the trace builder and the
//! constraints cannot drift apart. It is spec/14 constraint group 1 (Poseidon2
//! rounds), and the foundation every hash-binding group is built from.
//!
//! Layout: one full permutation per row (all round states are columns), ~509
//! columns. All constraints are local, so the trace repeats the single
//! permutation across a small power-of-two height.

use core::borrow::Borrow;
use core::ops::{Add, Mul};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof, VerificationError};

use scsv_core::hash::{Digest, DIGEST_LEN};
use scsv_core::F;

use crate::config::{config, ScsvConfig};
use crate::poseidon2_native::{internal_diag, permute_trace, EXT_ROUNDS_HALF, INT_ROUNDS, WIDTH};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL,
};

/// Column layout for one permutation (repr(C) so it aliases a `[T; NUM_COLS]`).
#[repr(C)]
pub struct PermCols<T> {
    pub input: [T; WIDTH],
    pub after_init_linear: [T; WIDTH],
    pub ext_init_x3: [[T; WIDTH]; EXT_ROUNDS_HALF],
    pub ext_init_out: [[T; WIDTH]; EXT_ROUNDS_HALF],
    pub int_x3: [T; INT_ROUNDS],
    pub int_out: [[T; WIDTH]; INT_ROUNDS],
    pub ext_final_x3: [[T; WIDTH]; EXT_ROUNDS_HALF],
    pub ext_final_out: [[T; WIDTH]; EXT_ROUNDS_HALF],
}

pub const NUM_COLS: usize = WIDTH * 2
    + EXT_ROUNDS_HALF * WIDTH * 2
    + INT_ROUNDS
    + INT_ROUNDS * WIDTH
    + EXT_ROUNDS_HALF * WIDTH * 2;

impl<T> Borrow<PermCols<T>> for [T] {
    fn borrow(&self) -> &PermCols<T> {
        debug_assert_eq!(self.len(), NUM_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<PermCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        &shorts[0]
    }
}

/// Trace height (a small power of two; the single permutation repeats).
const LOG_HEIGHT: usize = 2;
const HEIGHT: usize = 1 << LOG_HEIGHT;

// --- Generic linear layers (work for E = F and E = AB::Expr) ---

fn mat4<E>(x: [E; 4]) -> [E; 4]
where
    E: Clone + Add<Output = E>,
{
    let [x0, x1, x2, x3] = x;
    let t01 = x0.clone() + x1.clone();
    let t23 = x2.clone() + x3.clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + x1;
    let t01233 = t0123 + x3;
    [
        t01123.clone() + t01,     // 2*x0 + 3*x1 + x2 + x3
        t01123 + x2.clone() + x2, // x0 + 2*x1 + 3*x2 + x3
        t01233.clone() + t23,     // x0 + x1 + 2*x2 + 3*x3
        t01233 + x0.clone() + x0, // 3*x0 + x1 + x2 + 2*x3
    ]
}

fn external_linear<E>(state: &[E; WIDTH]) -> [E; WIDTH]
where
    E: Clone + Add<Output = E>,
{
    // mat4 on each group of 4.
    let mut m: Vec<E> = Vec::with_capacity(WIDTH);
    for g in 0..WIDTH / 4 {
        let group: [E; 4] = core::array::from_fn(|k| state[g * 4 + k].clone());
        let out = mat4(group);
        m.extend(out);
    }
    // sums[k] = Σ_{groups} m[group*4 + k]
    let sums: [E; 4] = core::array::from_fn(|k| {
        let mut acc = m[k].clone();
        for g in 1..WIDTH / 4 {
            acc = acc + m[g * 4 + k].clone();
        }
        acc
    });
    core::array::from_fn(|i| m[i].clone() + sums[i % 4].clone())
}

fn internal_linear<E>(state: &[E; WIDTH], diag: &[E; WIDTH]) -> [E; WIDTH]
where
    E: Clone + Add<Output = E> + Mul<Output = E>,
{
    let mut sum = state[0].clone();
    for s in state.iter().skip(1) {
        sum = sum + s.clone();
    }
    core::array::from_fn(|i| sum.clone() + diag[i].clone() * state[i].clone())
}

pub struct Poseidon2Air;

impl BaseAir<F> for Poseidon2Air {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        DIGEST_LEN
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        // x3 == t^3 is degree 3; x7 == x3^2·t and the linear layer over x7 is
        // also degree 3. No selectors (all constraints are local/unconditional).
        Some(3)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for Poseidon2Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let cols: &PermCols<AB::Var> = row.borrow();

        let diag_f = internal_diag();
        let diag: [AB::Expr; WIDTH] = core::array::from_fn(|i| AB::Expr::from(diag_f[i]));

        let var = |v: AB::Var| -> AB::Expr { v.into() };

        // Initial external linear layer.
        let input: [AB::Expr; WIDTH] = core::array::from_fn(|i| var(cols.input[i]));
        let init_lin = external_linear(&input);
        for (got, want) in init_lin.iter().zip(cols.after_init_linear.iter()) {
            builder.assert_eq(got.clone(), var(*want));
        }

        // A helper closure to constrain one external round.
        let assert_external = |builder: &mut AB,
                               a: &[AB::Expr; WIDTH],
                               rc: &[F; WIDTH],
                               x3: &[AB::Var; WIDTH],
                               out: &[AB::Var; WIDTH]| {
            let mut x7: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::ZERO);
            for (i, x7i) in x7.iter_mut().enumerate() {
                let t = a[i].clone() + AB::Expr::from(rc[i]);
                // x3 == t^3
                builder.assert_eq(var(x3[i]), t.clone() * t.clone() * t.clone());
                // x7 = x3^2 · t
                *x7i = var(x3[i]) * var(x3[i]) * t;
            }
            let lin = external_linear(&x7);
            for (got, want) in lin.iter().zip(out.iter()) {
                builder.assert_eq(got.clone(), var(*want));
            }
        };

        // External initial rounds.
        let mut a: [AB::Expr; WIDTH] = core::array::from_fn(|i| var(cols.after_init_linear[i]));
        for (rc, (x3, out)) in BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL
            .iter()
            .zip(cols.ext_init_x3.iter().zip(cols.ext_init_out.iter()))
        {
            assert_external(builder, &a, rc, x3, out);
            a = core::array::from_fn(|i| var(out[i]));
        }

        // Internal rounds.
        for (rc, (x3_col, out)) in BABYBEAR_POSEIDON2_RC_16_INTERNAL
            .iter()
            .zip(cols.int_x3.iter().zip(cols.int_out.iter()))
        {
            let t = a[0].clone() + AB::Expr::from(*rc);
            builder.assert_eq(var(*x3_col), t.clone() * t.clone() * t.clone());
            let x7_0 = var(*x3_col) * var(*x3_col) * t;
            let post_sbox: [AB::Expr; WIDTH] =
                core::array::from_fn(|i| if i == 0 { x7_0.clone() } else { a[i].clone() });
            let lin = internal_linear(&post_sbox, &diag);
            for (got, want) in lin.iter().zip(out.iter()) {
                builder.assert_eq(got.clone(), var(*want));
            }
            a = core::array::from_fn(|i| var(out[i]));
        }

        // External final rounds.
        for (rc, (x3, out)) in BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL
            .iter()
            .zip(cols.ext_final_x3.iter().zip(cols.ext_final_out.iter()))
        {
            assert_external(builder, &a, rc, x3, out);
            a = core::array::from_fn(|i| var(out[i]));
        }

        // Output digest binding: the first 8 lanes of the final state equal the
        // public digest. Copy the public values out first so the immutable
        // borrow of `builder` ends before the mutable `assert_eq` calls.
        let digest_pis: [AB::Expr; DIGEST_LEN] = {
            let pis = builder.public_values();
            core::array::from_fn(|i| pis[i].into())
        };
        for i in 0..DIGEST_LEN {
            builder.assert_eq(a[i].clone(), digest_pis[i].clone());
        }
    }
}

/// Flatten a `PermTrace` into one trace row's columns (repr(C) order).
fn write_row(input: [F; WIDTH], out: &mut [F]) {
    let t = permute_trace(input);
    let mut c = 0;
    let mut put = |vals: &[F], c: &mut usize| {
        out[*c..*c + vals.len()].copy_from_slice(vals);
        *c += vals.len();
    };
    put(&t.input, &mut c);
    put(&t.after_init_linear, &mut c);
    for r in 0..EXT_ROUNDS_HALF {
        put(&t.ext_init[r].0, &mut c);
    }
    for r in 0..EXT_ROUNDS_HALF {
        put(&t.ext_init[r].1, &mut c);
    }
    let int_x3: [F; INT_ROUNDS] = core::array::from_fn(|r| t.internal[r].0);
    put(&int_x3, &mut c);
    for r in 0..INT_ROUNDS {
        put(&t.internal[r].1, &mut c);
    }
    for r in 0..EXT_ROUNDS_HALF {
        put(&t.ext_final[r].0, &mut c);
    }
    for r in 0..EXT_ROUNDS_HALF {
        put(&t.ext_final[r].1, &mut c);
    }
    debug_assert_eq!(c, NUM_COLS);
}

/// Prove knowledge of a preimage for the permutation digest of `input`. Returns
/// the proof and the resulting 8-element digest (the public statement).
pub fn prove_permutation(input: [F; WIDTH]) -> (Proof<ScsvConfig>, Digest) {
    let mut values = F::zero_vec(HEIGHT * NUM_COLS);
    // The single permutation repeats across all rows (constraints are local).
    let mut first = vec![F::ZERO; NUM_COLS];
    write_row(input, &mut first);
    for row in 0..HEIGHT {
        values[row * NUM_COLS..(row + 1) * NUM_COLS].copy_from_slice(&first);
    }
    let digest = Digest(core::array::from_fn(
        |i| first[/* output lane i lives in the last ext_final_out block */ output_lane_offset() + i],
    ));

    let cfg = config();
    let proof = prove(
        &cfg,
        &Poseidon2Air,
        RowMajorMatrix::new(values, NUM_COLS),
        &digest.0,
    );
    (proof, digest)
}

/// Column offset of the final state (first lane of the last ext_final_out block).
fn output_lane_offset() -> usize {
    WIDTH * 2
        + EXT_ROUNDS_HALF * WIDTH // ext_init_x3
        + EXT_ROUNDS_HALF * WIDTH // ext_init_out
        + INT_ROUNDS // int_x3
        + INT_ROUNDS * WIDTH // int_out
        + EXT_ROUNDS_HALF * WIDTH // ext_final_x3
        + (EXT_ROUNDS_HALF - 1) * WIDTH // up to the last ext_final_out block
}

/// Fill a single trace row for `input` (exposed for negative tests that need to
/// tamper with an otherwise-valid trace).
pub fn fill_row_for_test(input: [F; WIDTH], out: &mut [F]) {
    write_row(input, out);
}

/// Verify a permutation proof against a public digest.
pub fn verify_permutation(
    proof: &Proof<ScsvConfig>,
    digest: &Digest,
) -> Result<(), VerificationError<impl core::fmt::Debug>> {
    let cfg = config();
    verify(&cfg, &Poseidon2Air, proof, &digest.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2_native::permute;

    #[test]
    fn digest_offset_is_output() {
        // The reconstructed digest from the trace equals the native output.
        let input: [F; WIDTH] = core::array::from_fn(|i| F::from_u32(i as u32 + 1));
        let mut row = vec![F::ZERO; NUM_COLS];
        write_row(input, &mut row);
        let out = permute(input);
        for i in 0..DIGEST_LEN {
            assert_eq!(row[output_lane_offset() + i], out[i]);
        }
    }
}
