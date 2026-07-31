//! Real end-to-end STARK proofs of Merkle-path openings at full FRI
//! parameters: proving in zero knowledge that a leaf is committed under a root.

use p3_field::PrimeCharacteristicRing;
use scsv_air::merkle_air::{native_root, prove_opening, verify_opening, DEPTH};
use scsv_core::hash::{h_compress, Digest};
use scsv_core::imt::MerklePath;
use scsv_core::F;

fn digest(n: u32) -> Digest {
    Digest(core::array::from_fn(|i| {
        F::from_u32(n.wrapping_mul(2_654_435_761).wrapping_add(i as u32))
    }))
}

fn path_and_bits(seed: u32) -> (MerklePath, [bool; DEPTH]) {
    let siblings: [Digest; scsv_core::imt::DEPTH] =
        core::array::from_fn(|i| digest(seed + 1000 + i as u32));
    let bits: [bool; DEPTH] = core::array::from_fn(|i| (seed >> i) & 1 == 1);
    (MerklePath { siblings }, bits)
}

#[test]
fn opening_proves_and_verifies() {
    let leaf = digest(7);
    let (path, bits) = path_and_bits(0b1011);
    let (proof, root) = prove_opening(leaf, &path, &bits);
    // The proven root matches the native fold.
    assert_eq!(root, native_root(leaf, &path, &bits));
    verify_opening(&proof, &leaf, &root).expect("verify");
}

#[test]
fn wrong_root_is_rejected() {
    let leaf = digest(9);
    let (path, bits) = path_and_bits(0b0110);
    let (proof, mut root) = prove_opening(leaf, &path, &bits);
    root.0[0] += F::ONE;
    assert!(
        verify_opening(&proof, &leaf, &root).is_err(),
        "root binding"
    );
}

#[test]
fn wrong_leaf_is_rejected() {
    let leaf = digest(11);
    let (path, bits) = path_and_bits(0b1111);
    let (proof, root) = prove_opening(leaf, &path, &bits);
    let other = digest(12);
    assert!(
        verify_opening(&proof, &other, &root).is_err(),
        "leaf binding"
    );
}

#[test]
fn direction_bits_matter() {
    // The same leaf and siblings with different direction bits give a different
    // root (unless the compress happens to collide, which it won't).
    let leaf = digest(3);
    let (path, _) = path_and_bits(0);
    let bits_a: [bool; DEPTH] = core::array::from_fn(|_| false);
    let bits_b: [bool; DEPTH] = core::array::from_fn(|_| true);
    assert_ne!(
        native_root(leaf, &path, &bits_a),
        native_root(leaf, &path, &bits_b)
    );
}

#[test]
fn native_fold_is_plain_compress_chain() {
    // Cross-check native_root against a hand-rolled compress chain.
    let leaf = digest(5);
    let (path, bits) = path_and_bits(0b0101);
    let mut cur = leaf;
    for (sibling, &bit) in path.siblings.iter().take(DEPTH).zip(bits.iter()) {
        cur = if bit {
            h_compress(sibling, &cur)
        } else {
            h_compress(&cur, sibling)
        };
    }
    assert_eq!(cur, native_root(leaf, &path, &bits));
}
