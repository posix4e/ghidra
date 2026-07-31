//! Indexed (sorted) Merkle tree with non-membership and insertion witnesses.
//! See `spec/04-STATE.md`.
//!
//! Leaves are `(key, nextKey)` pairs hashed under a per-tree domain; leaf `i`
//! links to the smallest key greater than `key_i`. `nextKey = 0` is the +∞
//! sentinel, and leaf 0 is the genesis leaf `(0, 0)`, so every real key
//! (which must be nonzero — digests are zero with negligible probability)
//! has a unique predecessor ("low") leaf. Non-membership of `k` is membership
//! of a low leaf with `low.key < k < low.nextKey` (or `nextKey = 0`).
//!
//! The tree has a fixed depth of 32 everywhere — tests included. Nodes are
//! stored sparsely; untouched subtrees use precomputed empty-subtree digests.
//!
//! The verification functions in this module are the native mirror of the
//! AIR's Merkle/non-membership/insert gadgets: the trace builder consumes the
//! exact same witnesses.

use std::collections::HashMap;

use crate::hash::{h_compress, h_sponge, Digest, Domain};
use crate::F;
use p3_field::PrimeCharacteristicRing;

/// Fixed tree depth (2^32 addressable leaves).
pub const DEPTH: usize = 32;

/// Leaf value payload: 4 field elements (amount limbs + spare for map trees;
/// all-zero for pure set trees like spent/frozen).
pub const VALUE_LEN: usize = 4;
pub type LeafValue = [F; VALUE_LEN];

pub const ZERO_VALUE: LeafValue = [F::ZERO; VALUE_LEN];

/// A leaf of the indexed tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdxLeaf {
    pub key: Digest,
    pub value: LeafValue,
    pub next_key: Digest,
}

impl IdxLeaf {
    pub fn hash(&self, domain: Domain) -> Digest {
        let mut input = [F::ZERO; 20];
        input[..8].copy_from_slice(&self.key.0);
        input[8..12].copy_from_slice(&self.value);
        input[12..].copy_from_slice(&self.next_key.0);
        h_sponge(domain, &input)
    }
}

/// A Merkle path: bottom-up sibling digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: [Digest; DEPTH],
}

/// Proof that `target` is absent: the low leaf, its index, and its path.
#[derive(Clone, Debug)]
pub struct NonMembershipWitness {
    pub target: Digest,
    pub low_index: u64,
    pub low_leaf: IdxLeaf,
    pub low_path: MerklePath,
}

/// Witness for inserting `key`: the pre-insert non-membership at root `r0`,
/// the low-leaf update (same siblings, giving root `r1`), and the append of
/// the new leaf at `new_index` (siblings valid against `r1`, giving `r2`).
#[derive(Clone, Debug)]
pub struct InsertWitness {
    pub non_membership: NonMembershipWitness,
    pub new_index: u64,
    pub new_leaf: IdxLeaf,
    pub append_path: MerklePath,
    pub root_before: Digest,
    pub root_mid: Digest,
    pub root_after: Digest,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImtError {
    #[error("key already present")]
    AlreadyPresent,
    #[error("key is the zero sentinel")]
    ZeroKey,
    #[error("tree is full")]
    Full,
}

/// Sparse fixed-depth indexed Merkle tree.
#[derive(Clone, Debug)]
pub struct IndexedMerkleTree {
    domain: Domain,
    /// Leaves in append order; leaf 0 is the genesis (0,0) leaf.
    leaves: Vec<IdxLeaf>,
    /// Sparse node store: (level, index) -> digest. Level 0 = leaf hashes,
    /// level DEPTH = root. Missing entries are empty-subtree defaults.
    nodes: HashMap<(u8, u64), Digest>,
    /// Empty-subtree digests per level: default[0] = hash of an all-zero leaf
    /// slot (Digest::ZERO), defaults[l+1] = compress(defaults[l], defaults[l]).
    defaults: [Digest; DEPTH + 1],
}

impl IndexedMerkleTree {
    /// New tree containing only the genesis (0,0) leaf.
    pub fn new(domain: Domain) -> Self {
        let mut defaults = [Digest::ZERO; DEPTH + 1];
        // Empty leaf slots contribute the all-zero digest (NOT a hashed leaf —
        // absent slots are structurally distinct from any real leaf hash).
        for l in 0..DEPTH {
            defaults[l + 1] = h_compress(&defaults[l], &defaults[l]);
        }
        let mut t = Self {
            domain,
            leaves: Vec::new(),
            nodes: HashMap::new(),
            defaults,
        };
        let genesis = IdxLeaf {
            key: Digest::ZERO,
            value: ZERO_VALUE,
            next_key: Digest::ZERO,
        };
        t.leaves.push(genesis);
        t.write_leaf(0, genesis);
        t
    }

    pub fn domain(&self) -> Domain {
        self.domain
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        // The genesis leaf is structural; "empty" means no real keys.
        self.leaves.len() == 1
    }

    pub fn root(&self) -> Digest {
        self.node(DEPTH as u8, 0)
    }

    fn node(&self, level: u8, index: u64) -> Digest {
        *self
            .nodes
            .get(&(level, index))
            .unwrap_or(&self.defaults[level as usize])
    }

    fn write_leaf(&mut self, index: u64, leaf: IdxLeaf) {
        let mut h = leaf.hash(self.domain);
        self.nodes.insert((0, index), h);
        let mut idx = index;
        for level in 0..DEPTH as u8 {
            let sib = self.node(level, idx ^ 1);
            h = if idx & 1 == 0 {
                h_compress(&h, &sib)
            } else {
                h_compress(&sib, &h)
            };
            idx >>= 1;
            self.nodes.insert((level + 1, idx), h);
        }
    }

    fn path(&self, index: u64) -> MerklePath {
        let mut siblings = [Digest::ZERO; DEPTH];
        let mut idx = index;
        for (level, sib) in siblings.iter_mut().enumerate() {
            *sib = self.node(level as u8, idx ^ 1);
            idx >>= 1;
        }
        MerklePath { siblings }
    }

    /// Locate the unique low leaf for `key`: `low.key < key` and
    /// (`key < low.nextKey` or `low.nextKey = 0`). Returns None if `key` is
    /// present.
    fn find_low(&self, key: &Digest) -> Option<u64> {
        // Linear scan; fine natively for wallet-scale trees. (Wallets hold
        // their own spent sets; frozen sets are issuer-scale.)
        let mut best: Option<u64> = None;
        for (i, leaf) in self.leaves.iter().enumerate() {
            if leaf.key == *key {
                return None;
            }
            if leaf.key.key_cmp(key) == core::cmp::Ordering::Less {
                match best {
                    None => best = Some(i as u64),
                    Some(b) => {
                        if self.leaves[b as usize].key.key_cmp(&leaf.key)
                            == core::cmp::Ordering::Less
                        {
                            best = Some(i as u64);
                        }
                    }
                }
            }
        }
        best
    }

    pub fn contains(&self, key: &Digest) -> bool {
        self.leaves.iter().any(|l| l.key == *key)
    }

    /// Produce a non-membership witness for `key`, or None if present/zero.
    pub fn prove_non_membership(&self, key: &Digest) -> Option<NonMembershipWitness> {
        if key.is_zero() {
            return None;
        }
        let low_index = self.find_low(key)?;
        Some(NonMembershipWitness {
            target: *key,
            low_index,
            low_leaf: self.leaves[low_index as usize],
            low_path: self.path(low_index),
        })
    }

    /// Insert `key` with an all-zero value (set semantics).
    pub fn insert(&mut self, key: Digest) -> Result<InsertWitness, ImtError> {
        self.insert_with_value(key, ZERO_VALUE)
    }

    /// Insert `key` with `value`, returning the three-root witness.
    pub fn insert_with_value(
        &mut self,
        key: Digest,
        value: LeafValue,
    ) -> Result<InsertWitness, ImtError> {
        if key.is_zero() {
            return Err(ImtError::ZeroKey);
        }
        let non_membership = self
            .prove_non_membership(&key)
            .ok_or(ImtError::AlreadyPresent)?;
        if self.leaves.len() as u64 >= 1u64 << DEPTH {
            return Err(ImtError::Full);
        }
        let root_before = self.root();

        // Step 1: rewrite the low leaf to point at the new key.
        let low_index = non_membership.low_index;
        let old_low = self.leaves[low_index as usize];
        let new_low = IdxLeaf {
            key: old_low.key,
            value: old_low.value,
            next_key: key,
        };
        self.leaves[low_index as usize] = new_low;
        self.write_leaf(low_index, new_low);
        let root_mid = self.root();

        // Step 2: append the new leaf, inheriting the old low's successor.
        let new_index = self.leaves.len() as u64;
        let append_path = self.path(new_index);
        let new_leaf = IdxLeaf {
            key,
            value,
            next_key: old_low.next_key,
        };
        self.leaves.push(new_leaf);
        self.write_leaf(new_index, new_leaf);
        let root_after = self.root();

        Ok(InsertWitness {
            non_membership,
            new_index,
            new_leaf,
            append_path,
            root_before,
            root_mid,
            root_after,
        })
    }
}

/// Witness for updating the value of an existing leaf in place.
#[derive(Clone, Debug)]
pub struct UpdateWitness {
    pub index: u64,
    pub old_leaf: IdxLeaf,
    pub new_leaf: IdxLeaf,
    pub path: MerklePath,
    pub root_before: Digest,
    pub root_after: Digest,
}

impl IndexedMerkleTree {
    /// Current leaf for `key`, if present.
    pub fn get(&self, key: &Digest) -> Option<(u64, IdxLeaf)> {
        self.leaves
            .iter()
            .position(|l| l.key == *key)
            .map(|i| (i as u64, self.leaves[i]))
    }

    /// Replace the value of an existing `key`, returning the witness.
    pub fn update_value(
        &mut self,
        key: &Digest,
        value: LeafValue,
    ) -> Result<UpdateWitness, ImtError> {
        let (index, old_leaf) = self.get(key).ok_or(ImtError::ZeroKey)?;
        let root_before = self.root();
        let path = self.path(index);
        let new_leaf = IdxLeaf {
            key: old_leaf.key,
            value,
            next_key: old_leaf.next_key,
        };
        self.leaves[index as usize] = new_leaf;
        self.write_leaf(index, new_leaf);
        Ok(UpdateWitness {
            index,
            old_leaf,
            new_leaf,
            path,
            root_before,
            root_after: self.root(),
        })
    }
}

/// Verify an in-place value update. Mirrors the AIR's balance-write gadget.
pub fn verify_update(domain: Domain, w: &UpdateWitness) -> bool {
    w.old_leaf.key == w.new_leaf.key
        && w.old_leaf.next_key == w.new_leaf.next_key
        && path_root(w.old_leaf.hash(domain), w.index, &w.path) == w.root_before
        && path_root(w.new_leaf.hash(domain), w.index, &w.path) == w.root_after
}

/// Recompute a root from a leaf hash, its index, and a path.
pub fn path_root(leaf_hash: Digest, index: u64, path: &MerklePath) -> Digest {
    let mut h = leaf_hash;
    let mut idx = index;
    for sib in path.siblings.iter() {
        h = if idx & 1 == 0 {
            h_compress(&h, sib)
        } else {
            h_compress(sib, &h)
        };
        idx >>= 1;
    }
    h
}

/// Verify a non-membership witness against `root`. Mirrors the AIR gadget:
/// low-leaf ordering plus one Merkle opening.
pub fn verify_non_membership(domain: Domain, w: &NonMembershipWitness, root: &Digest) -> bool {
    use core::cmp::Ordering::Less;
    if w.target.is_zero() {
        return false;
    }
    let key_ok = w.low_leaf.key.key_cmp(&w.target) == Less
        && (w.low_leaf.next_key.is_zero() || w.target.key_cmp(&w.low_leaf.next_key) == Less);
    if !key_ok {
        return false;
    }
    path_root(w.low_leaf.hash(domain), w.low_index, &w.low_path) == *root
}

/// Verify a full insert witness chain `root_before -> root_mid -> root_after`.
/// Mirrors the AIR's three-phase spent-accumulator gadget.
pub fn verify_insert(domain: Domain, w: &InsertWitness) -> bool {
    let nm = &w.non_membership;
    // Non-membership against the starting root.
    if !verify_non_membership(domain, nm, &w.root_before) {
        return false;
    }
    // Low-leaf rewrite with the same siblings (value untouched).
    let new_low = IdxLeaf {
        key: nm.low_leaf.key,
        value: nm.low_leaf.value,
        next_key: nm.target,
    };
    if path_root(new_low.hash(domain), nm.low_index, &nm.low_path) != w.root_mid {
        return false;
    }
    // Append: the slot must open as an empty (all-zero) node against root_mid,
    // and rewriting it with the new leaf must give root_after.
    if path_root(Digest::ZERO, w.new_index, &w.append_path) != w.root_mid {
        return false;
    }
    if w.new_leaf.key != nm.target || w.new_leaf.next_key != nm.low_leaf.next_key {
        return false;
    }
    path_root(w.new_leaf.hash(domain), w.new_index, &w.append_path) == w.root_after
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::bytes32_to_limbs;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn key(n: u64) -> Digest {
        h_sponge(
            Domain::CoinId,
            &bytes32_to_limbs(&{
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&n.to_le_bytes());
                b
            }),
        )
    }

    #[test]
    fn insert_and_witness_roundtrip() {
        let mut t = IndexedMerkleTree::new(Domain::SpentLeaf);
        let mut roots = vec![t.root()];
        for n in 1..=20u64 {
            let w = t.insert(key(n)).unwrap();
            assert!(verify_insert(Domain::SpentLeaf, &w), "insert witness {n}");
            assert_eq!(w.root_before, *roots.last().unwrap());
            assert_eq!(w.root_after, t.root());
            roots.push(t.root());
        }
        // Every inserted key is now present; fresh keys are provably absent.
        for n in 1..=20u64 {
            assert!(t.contains(&key(n)));
            assert!(t.prove_non_membership(&key(n)).is_none());
        }
        let w = t.prove_non_membership(&key(999)).unwrap();
        assert!(verify_non_membership(Domain::SpentLeaf, &w, &t.root()));
    }

    #[test]
    fn duplicate_insert_rejected() {
        let mut t = IndexedMerkleTree::new(Domain::SpentLeaf);
        t.insert(key(1)).unwrap();
        assert!(matches!(t.insert(key(1)), Err(ImtError::AlreadyPresent)));
    }

    #[test]
    fn tampered_witnesses_rejected() {
        let mut t = IndexedMerkleTree::new(Domain::FrozenLeaf);
        for n in 1..10u64 {
            t.insert(key(n)).unwrap();
        }
        let root = t.root();
        let good = t.prove_non_membership(&key(50)).unwrap();
        assert!(verify_non_membership(Domain::FrozenLeaf, &good, &root));

        // Wrong domain.
        assert!(!verify_non_membership(Domain::SpentLeaf, &good, &root));
        // Wrong root.
        assert!(!verify_non_membership(Domain::FrozenLeaf, &good, &key(1)));
        // Claiming non-membership of a present key with a mismatched low leaf.
        let mut bad = good.clone();
        bad.target = key(3);
        assert!(!verify_non_membership(Domain::FrozenLeaf, &bad, &root));
        // Perturbed sibling.
        let mut bad = good.clone();
        bad.low_path.siblings[5] = key(1);
        assert!(!verify_non_membership(Domain::FrozenLeaf, &bad, &root));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn matches_btreeset_model(ops in proptest::collection::vec(0u64..500, 1..60)) {
            let mut t = IndexedMerkleTree::new(Domain::SpentLeaf);
            let mut model: BTreeSet<u64> = BTreeSet::new();
            for op in ops {
                let k = key(op + 1); // avoid n=0 -> distinct nonzero keys
                if model.contains(&(op + 1)) {
                    prop_assert!(t.contains(&k));
                    prop_assert!(t.insert(k).is_err());
                    prop_assert!(t.prove_non_membership(&k).is_none());
                } else {
                    let w = t.prove_non_membership(&k).unwrap();
                    prop_assert!(verify_non_membership(Domain::SpentLeaf, &w, &t.root()));
                    let iw = t.insert(k).unwrap();
                    prop_assert!(verify_insert(Domain::SpentLeaf, &iw));
                    model.insert(op + 1);
                }
                prop_assert_eq!(t.len(), model.len() + 1); // + genesis leaf
            }
        }
    }
}
