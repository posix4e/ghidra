//! A hand-written AIR proving a Merkle-path opening: that a public leaf digest
//! hashes up a witnessed path (siblings + direction bits) to a public root,
//! using the protocol's `h_compress` (one Poseidon2 permutation per level).
//!
//! This is the coin-commitment / accumulator membership primitive (spec/14
//! constraint group 3): "this leaf is in the committed tree", proven in zero
//! knowledge. It builds directly on the validated permutation gadget
//! ([`crate::poseidon2_air`]).
//!
//! Layout: one tree level per row. Each row embeds a full permutation (the
//! level's compression) plus the sibling digest, the running current digest,
//! and the direction bit. Rows chain: row `r`'s output feeds row `r+1`'s
//! current digest; the first row's current is the leaf, the last row's output
//! is the root.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof, VerificationError};

use scsv_core::hash::{h_compress, Digest, DIGEST_LEN};
use scsv_core::imt::MerklePath;
use scsv_core::F;

use crate::config::{config, ScsvConfig};
use crate::poseidon2_air::{constrain_perm, PermCols, NUM_COLS as PERM_COLS};
use crate::poseidon2_native::WIDTH;

/// Tree depth this AIR proves. The real indexed tree is depth 32; this gadget
/// is parameterized by rows and demonstrated at depth 8 (a power of two so it
/// is a valid uni-stark height). Raising it to 32 is a constant change.
pub const DEPTH: usize = 8;

/// Per-row columns: the level's permutation, its sibling, the running current
/// digest, and the direction bit.
#[repr(C)]
pub struct MerkleCols<T> {
    pub perm: PermCols<T>,
    pub sibling: [T; DIGEST_LEN],
    pub current: [T; DIGEST_LEN],
    pub bit: T,
}

pub const NUM_COLS: usize = PERM_COLS + DIGEST_LEN + DIGEST_LEN + 1;

impl<T> Borrow<MerkleCols<T>> for [T] {
    fn borrow(&self) -> &MerkleCols<T> {
        debug_assert_eq!(self.len(), NUM_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MerkleCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        &shorts[0]
    }
}

pub struct MerkleAir;

impl BaseAir<F> for MerkleAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        // leaf digest (8) + root digest (8)
        2 * DIGEST_LEN
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        // Permutation constraints are degree 3; the bit-selected input routing
        // (bit·(sibling-current)) is degree 2. Under the transition/first/last
        // selectors, the max is 3 + 1 = 4.
        Some(4)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for MerkleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();
        let local: &MerkleCols<AB::Var> = local_slice.borrow();
        let next: &MerkleCols<AB::Var> = next_slice.borrow();

        let var = |v: AB::Var| -> AB::Expr { v.into() };

        // Direction bit is boolean.
        builder.assert_bool(local.bit);

        // Input routing: the permutation input is (current, sibling) ordered by
        // the bit. bit=0 ⇒ [current ‖ sibling]; bit=1 ⇒ [sibling ‖ current].
        //   input[i]       = current[i] + bit·(sibling[i] - current[i])
        //   input[i+8]     = sibling[i] + bit·(current[i] - sibling[i])
        for i in 0..DIGEST_LEN {
            let cur = var(local.current[i]);
            let sib = var(local.sibling[i]);
            let left = cur.clone() + var(local.bit) * (sib.clone() - cur.clone());
            let right = sib.clone() + var(local.bit) * (cur - sib);
            builder.assert_eq(var(local.perm.input[i]), left);
            builder.assert_eq(var(local.perm.input[DIGEST_LEN + i]), right);
        }

        // The permutation round chain; `out` is the level's compressed digest.
        let out = constrain_perm(builder, &local.perm);

        // Public leaf/root bindings.
        let (leaf, root): ([AB::Expr; DIGEST_LEN], [AB::Expr; DIGEST_LEN]) = {
            let pis = builder.public_values();
            (
                core::array::from_fn(|i| pis[i].into()),
                core::array::from_fn(|i| pis[DIGEST_LEN + i].into()),
            )
        };

        // First row: current digest is the leaf.
        {
            let mut first = builder.when_first_row();
            for (cur, lf) in local.current.iter().zip(leaf.iter()) {
                first.assert_eq(var(*cur), lf.clone());
            }
        }

        // Transition: next row's current digest is this level's output.
        {
            let mut trans = builder.when_transition();
            for (nc, o) in next.current.iter().zip(out.iter()) {
                trans.assert_eq(var(*nc), o.clone());
            }
        }

        // Last row: the level output is the root.
        {
            let mut last = builder.when_last_row();
            for (o, rt) in out.iter().zip(root.iter()) {
                last.assert_eq(o.clone(), rt.clone());
            }
        }
    }
}

/// Fill one Merkle row: the permutation of `h_compress(left, right)` plus the
/// sibling / current / bit routing. Returns the level output digest.
fn write_row(current: Digest, sibling: Digest, bit: bool, out: &mut [F]) -> Digest {
    // Order the compression inputs per the direction bit.
    let (left, right) = if bit {
        (sibling, current)
    } else {
        (current, sibling)
    };
    let mut input = [F::ZERO; WIDTH];
    input[..DIGEST_LEN].copy_from_slice(&left.0);
    input[DIGEST_LEN..].copy_from_slice(&right.0);

    // Permutation columns first (repr(C): perm is the leading field).
    crate::poseidon2_air::fill_row_for_test(input, &mut out[..PERM_COLS]);

    // Then sibling, current, bit.
    let mut c = PERM_COLS;
    out[c..c + DIGEST_LEN].copy_from_slice(&sibling.0);
    c += DIGEST_LEN;
    out[c..c + DIGEST_LEN].copy_from_slice(&current.0);
    c += DIGEST_LEN;
    out[c] = F::from_bool(bit);

    h_compress(&left, &right)
}

/// Prove that `leaf` opens to `root` along `path` with `bits` (LSB = level 0).
/// `bits[i] = true` means the current digest is the RIGHT child at level `i`.
pub fn prove_opening(
    leaf: Digest,
    path: &MerklePath,
    bits: &[bool; DEPTH],
) -> (Proof<ScsvConfig>, Digest) {
    let mut values = F::zero_vec(DEPTH * NUM_COLS);
    let mut current = leaf;
    for level in 0..DEPTH {
        let row = &mut values[level * NUM_COLS..(level + 1) * NUM_COLS];
        current = write_row(current, path.siblings[level], bits[level], row);
    }
    let root = current;
    let mut pubs = Vec::with_capacity(2 * DIGEST_LEN);
    pubs.extend_from_slice(&leaf.0);
    pubs.extend_from_slice(&root.0);

    let cfg = config();
    let proof = prove(
        &cfg,
        &MerkleAir,
        RowMajorMatrix::new(values, NUM_COLS),
        &pubs,
    );
    (proof, root)
}

/// Verify a Merkle-opening proof binding `leaf` to `root`.
pub fn verify_opening(
    proof: &Proof<ScsvConfig>,
    leaf: &Digest,
    root: &Digest,
) -> Result<(), VerificationError<impl core::fmt::Debug>> {
    let mut pubs = Vec::with_capacity(2 * DIGEST_LEN);
    pubs.extend_from_slice(&leaf.0);
    pubs.extend_from_slice(&root.0);
    let cfg = config();
    verify(&cfg, &MerkleAir, proof, &pubs)
}

/// Native reference: fold a leaf up a path with direction bits to its root.
pub fn native_root(leaf: Digest, path: &MerklePath, bits: &[bool; DEPTH]) -> Digest {
    let mut cur = leaf;
    for (sibling, &bit) in path.siblings.iter().take(DEPTH).zip(bits.iter()) {
        let (l, r) = if bit {
            (*sibling, cur)
        } else {
            (cur, *sibling)
        };
        cur = h_compress(&l, &r);
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sib(n: u32) -> Digest {
        Digest(core::array::from_fn(|i| F::from_u32(n * 100 + i as u32)))
    }

    #[test]
    fn write_row_matches_native_compress() {
        let cur = sib(1);
        let s = sib(2);
        let mut row = vec![F::ZERO; NUM_COLS];
        let out = write_row(cur, s, true, &mut row);
        assert_eq!(out, h_compress(&s, &cur));
    }
}
