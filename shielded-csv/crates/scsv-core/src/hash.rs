//! The protocol hash: Poseidon2 over BabyBear, width 16 (rate 8, capacity 8),
//! using the fixed round constants shipped by `p3-baby-bear` so native and
//! in-circuit evaluation agree by construction. See `spec/01-CRYPTO.md`.
//!
//! Two modes:
//! - [`h_sponge`]: domain- and length-bound sponge over field elements,
//!   squeezing one [`Digest`]. Capacity lanes are initialized with the domain
//!   tag and input length, which gives cross-purpose and cross-length
//!   separation without padding schemes.
//! - [`h_compress`]: one-permutation 2-to-1 node compression for Merkle trees
//!   (truncated permutation, as used across the Plonky3 ecosystem). Tree-type
//!   separation lives in the domain-tagged *leaf* hashes, not in inner nodes.

use std::sync::OnceLock;

use p3_baby_bear::{default_babybear_poseidon2_16, Poseidon2BabyBear};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

use crate::field::{f_from_u32, f_to_u32, F};

/// Sponge/permutation width in field elements.
pub const WIDTH: usize = 16;
/// Sponge rate (absorbed/squeezed lanes per permutation).
pub const RATE: usize = 8;
/// Digest length in field elements (~124-bit collision resistance).
pub const DIGEST_LEN: usize = 8;

/// A protocol digest: 8 BabyBear elements.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Digest(pub [F; DIGEST_LEN]);

impl Digest {
    pub const ZERO: Digest = Digest([F::ZERO; DIGEST_LEN]);

    /// Canonical 32-byte encoding: 8 little-endian `u32`s, each `< 2^31`.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, l) in self.0.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&f_to_u32(*l).to_le_bytes());
        }
        out
    }

    /// Strict decode of [`Self::to_bytes`]; rejects non-canonical values.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Digest> {
        let mut limbs = [F::ZERO; DIGEST_LEN];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let v = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
            if v >= crate::field::P {
                return None;
            }
            *limb = f_from_u32(v);
        }
        Some(Digest(limbs))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Lexicographic comparison over limbs in index order — the canonical key
    /// order of the indexed Merkle trees (`spec/04-STATE.md`). This is what the
    /// AIR's comparison gadget mirrors.
    pub fn key_cmp(&self, other: &Digest) -> core::cmp::Ordering {
        for i in 0..DIGEST_LEN {
            match f_to_u32(self.0[i]).cmp(&f_to_u32(other.0[i])) {
                core::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        core::cmp::Ordering::Equal
    }

    pub fn is_zero(&self) -> bool {
        *self == Digest::ZERO
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Digest({}…)", &self.to_hex()[..16])
    }
}

/// Domain tags for every hashed structure. The numeric values are protocol
/// constants; changing any of them changes every derived identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Domain {
    /// Account state commitment (`spec/04-STATE.md`).
    StateCom = 1,
    /// Account identity (`spec/02-KEYS-ACCOUNTS.md`).
    AccountId = 2,
    /// Address commitment to an accountID.
    Addr = 3,
    /// Input-coin leaf inside an outputs commitment tree.
    CoinLeaf = 4,
    /// Coin identity from (creatingTxHash, outIndex).
    CoinId = 5,
    /// Indexed-tree leaf of the spent accumulator.
    SpentLeaf = 6,
    /// Indexed-tree leaf of a frozen set.
    FrozenLeaf = 7,
    /// Indexed-tree leaf of the balances tree.
    BalanceLeaf = 8,
    /// Asset genesis -> assetId (`spec/09-ISSUANCE.md`).
    GenesisH = 9,
    /// Issuer record hashing (`spec/08-RECORDS.md`).
    Record = 10,
    /// Per-input link tuple chain -> inputsDigest.
    LinkTuple = 11,
    /// Fiat-Shamir binding of the public-input vector (S2).
    PiBind = 12,
    /// Nullifier public-key hash held in account state.
    NullifierPk = 13,
    /// Transaction essence -> txHash.
    TxEssence = 14,
    /// Bundle/evidence content addressing.
    Bundle = 15,
}

fn perm() -> &'static Poseidon2BabyBear<16> {
    static PERM: OnceLock<Poseidon2BabyBear<16>> = OnceLock::new();
    PERM.get_or_init(default_babybear_poseidon2_16)
}

/// Apply the raw width-16 Poseidon2 permutation. Exposed so the AIR trace
/// builder and tests share the exact native permutation.
pub fn permute(state: &mut [F; WIDTH]) {
    perm().permute_mut(state);
}

/// Domain- and length-bound sponge. Absorbs `input` in rate-8 chunks
/// (zero-padded), with capacity initialized to `[domain, len, 0, …]`; squeezes
/// the first 8 lanes.
pub fn h_sponge(domain: Domain, input: &[F]) -> Digest {
    let mut state = [F::ZERO; WIDTH];
    state[RATE] = f_from_u32(domain as u32);
    state[RATE + 1] = f_from_u32(input.len() as u32);
    let mut chunks = input.chunks(RATE).peekable();
    if chunks.peek().is_none() {
        // Empty input still runs one permutation over the initialized state.
        permute(&mut state);
    }
    for chunk in chunks {
        for (lane, x) in state.iter_mut().zip(chunk.iter()) {
            *lane += *x;
        }
        permute(&mut state);
    }
    Digest(state[..DIGEST_LEN].try_into().unwrap())
}

/// One-permutation 2-to-1 compression: `perm(left ‖ right)[0..8]`.
pub fn h_compress(left: &Digest, right: &Digest) -> Digest {
    let mut state = [F::ZERO; WIDTH];
    state[..DIGEST_LEN].copy_from_slice(&left.0);
    state[DIGEST_LEN..].copy_from_slice(&right.0);
    permute(&mut state);
    Digest(state[..DIGEST_LEN].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::bytes32_to_limbs;

    /// Committed test vectors: any change to the Poseidon2 instance, the sponge
    /// framing, or the compress construction must show up here loudly. If this
    /// test fails, the protocol's identifiers have changed — that is a
    /// consensus break, not a refactor.
    #[test]
    fn committed_vectors() {
        let empty = h_sponge(Domain::StateCom, &[]);
        let one = h_sponge(Domain::StateCom, &[F::ONE]);
        let other_domain = h_sponge(Domain::AccountId, &[F::ONE]);
        let compress = h_compress(&empty, &one);

        assert_eq!(
            empty.to_hex(),
            "3961f65c9d82d5153703214f83e1e47144f9e7069f24320fc0aa843c38040066"
        );
        assert_eq!(
            one.to_hex(),
            "06f755310f3a132f7c242d104fff1553795d7f3c3e4e910b8b1f8f54c80b2773"
        );
        assert_eq!(
            other_domain.to_hex(),
            "4b05383c6889da00c4ed664b1d21d12399ef7f05f62e2468e644395957939120"
        );
        assert_eq!(
            compress.to_hex(),
            "aecbf839a8ab1026dba4f110f23bd82d05e2c42db19f291396820f0cfe8b943e"
        );
    }

    #[test]
    fn domain_and_length_separate() {
        assert_ne!(h_sponge(Domain::StateCom, &[]), h_sponge(Domain::Addr, &[]));
        // Same field content, different declared lengths (trailing zero).
        assert_ne!(
            h_sponge(Domain::StateCom, &[F::ONE]),
            h_sponge(Domain::StateCom, &[F::ONE, F::ZERO])
        );
    }

    #[test]
    fn digest_bytes_roundtrip() {
        let d = h_sponge(Domain::CoinId, &bytes32_to_limbs(&[7u8; 32]));
        assert_eq!(Digest::from_bytes(&d.to_bytes()).unwrap(), d);
        // Non-canonical (>= P) limbs are rejected.
        let mut bad = d.to_bytes();
        bad[0..4].copy_from_slice(&crate::field::P.to_le_bytes());
        assert!(Digest::from_bytes(&bad).is_none());
    }

    #[test]
    fn key_cmp_is_lexicographic() {
        let a = Digest([F::ZERO; 8]);
        let mut b = a;
        b.0[7] = F::ONE;
        assert_eq!(a.key_cmp(&b), core::cmp::Ordering::Less);
        let mut c = a;
        c.0[0] = F::ONE;
        assert_eq!(c.key_cmp(&b), core::cmp::Ordering::Greater);
    }
}
