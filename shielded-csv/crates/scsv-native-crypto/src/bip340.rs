//! BIP340 Schnorr with explicit nonce control, plus the sign-to-contract
//! nullifier construction of `spec/06-NULLIFIERS.md`.
//!
//! Signatures produced here are standard BIP340 (fixed-message) signatures —
//! any BIP340 verifier accepts them. What is non-standard is only *how the
//! nonce is chosen*: `R = R0 + H_tag("SCSV/s2c", R0.x ‖ txHash)·G`, so the
//! published nullifier commits to the transaction hash while remaining an
//! ordinary key + signature pair. Everything here is native-only; nothing in
//! this crate ever enters the AIR.

use k256::elliptic_curve::{
    group::Group, ops::Reduce, point::AffineCoordinates, point::DecompressPoint,
    sec1::ToEncodedPoint, subtle::Choice, PrimeField,
};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use sha2::{Digest as _, Sha256};

/// x-only public key bytes.
pub type XOnlyBytes = [u8; 32];

/// A published nullifier: x-only key + BIP340 signature (`spec/06`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullifierSig {
    pub pk: XOnlyBytes,
    pub sig: [u8; 64],
}

/// The sign-to-contract opening: the pre-tweak nonce point, compressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S2cOpening {
    pub r0: [u8; 33],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid secret scalar")]
    BadSecret,
    #[error("invalid point encoding")]
    BadPoint,
}

/// BIP340 tagged hash: `sha256(sha256(tag) ‖ sha256(tag) ‖ data…)`.
pub fn tagged_hash(tag: &str, chunks: &[&[u8]]) -> [u8; 32] {
    let tag_digest = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_digest);
    h.update(tag_digest);
    for c in chunks {
        h.update(c);
    }
    h.finalize().into()
}

fn scalar_from_hash(bytes: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into())
}

fn lift_x(x: &XOnlyBytes) -> Option<AffinePoint> {
    Option::from(AffinePoint::decompress(&(*x).into(), Choice::from(0u8)))
}

fn x_bytes(p: &AffinePoint) -> [u8; 32] {
    p.x().into()
}

fn compress33(p: &AffinePoint) -> [u8; 33] {
    let enc = p.to_encoded_point(true);
    enc.as_bytes()
        .try_into()
        .expect("compressed point is 33 bytes")
}

fn decompress33(b: &[u8; 33]) -> Option<AffinePoint> {
    if b[0] != 0x02 && b[0] != 0x03 {
        return None;
    }
    let x: [u8; 32] = b[1..].try_into().unwrap();
    Option::from(AffinePoint::decompress(&x.into(), Choice::from(b[0] & 1)))
}

/// A nullifier keypair, normalized so the public key has even Y (BIP340).
#[derive(Clone)]
pub struct NullifierKeypair {
    /// Even-Y-normalized secret.
    sk: Scalar,
    pub pk: XOnlyBytes,
}

impl NullifierKeypair {
    /// Deterministically derive a nullifier keypair from an account secret and
    /// a 32-byte context (in the v1 wallet, a fresh address's randomness). Each
    /// address thus has its own nullifier key, committed into the coin sent
    /// there, so spending that coin twice yields the same nullifier public key —
    /// which the chain's first-occurrence rule rejects. This is the per-coin
    /// double-spend prevention of the v1 wallet (`spec/06-NULLIFIERS.md`,
    /// simplification documented in `spec/19-WALLET.md`).
    pub fn derive(account_sk: &[u8; 32], context: &[u8; 32]) -> Self {
        let seed = tagged_hash("SCSV/coin-nullifier/v1", &[account_sk, context]);
        // from_seed only fails on the zero scalar (negligible for a hash output).
        Self::from_seed(&seed).expect("nonzero derived nullifier scalar")
    }

    /// Derive a keypair from 32 seed bytes (reduced mod n; the caller supplies
    /// OS randomness — this crate stays deterministic).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let sk = scalar_from_hash(tagged_hash("SCSV/nullifier-key/v1", &[seed]));
        if sk == Scalar::ZERO {
            return Err(CryptoError::BadSecret);
        }
        let point = (ProjectivePoint::GENERATOR * sk).to_affine();
        let (sk, pk_point) = if bool::from(point.y_is_odd()) {
            let neg = -sk;
            (neg, (ProjectivePoint::GENERATOR * neg).to_affine())
        } else {
            (sk, point)
        };
        Ok(Self {
            sk,
            pk: x_bytes(&pk_point),
        })
    }

    /// The secret bytes (for wallet persistence). Even-Y normalized.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes().into()
    }

    pub fn from_secret_bytes(b: &[u8; 32]) -> Result<Self, CryptoError> {
        let sk =
            Option::<Scalar>::from(Scalar::from_repr((*b).into())).ok_or(CryptoError::BadSecret)?;
        if sk == Scalar::ZERO {
            return Err(CryptoError::BadSecret);
        }
        let point = (ProjectivePoint::GENERATOR * sk).to_affine();
        if bool::from(point.y_is_odd()) {
            return Err(CryptoError::BadSecret);
        }
        Ok(Self {
            sk,
            pk: x_bytes(&point),
        })
    }
}

/// The fixed protocol message every nullifier signs (`spec/06`).
pub fn nullifier_message(chain_id: &[u8; 32]) -> [u8; 32] {
    tagged_hash("SCSV/nullifier-msg/v1", &[chain_id])
}

/// The sign-to-contract tweak scalar for `(R0, txHash)`.
fn s2c_tweak(r0: &[u8; 33], tx_hash: &[u8; 32]) -> Scalar {
    scalar_from_hash(tagged_hash("SCSV/s2c", &[r0, tx_hash]))
}

/// BIP340 challenge scalar.
fn challenge(rx: &[u8; 32], px: &XOnlyBytes, msg: &[u8; 32]) -> Scalar {
    scalar_from_hash(tagged_hash("BIP0340/challenge", &[rx, px, msg]))
}

/// Sign the fixed protocol message with a nonce committing to `tx_hash`.
/// Returns the on-chain nullifier and the off-chain opening. Deterministic:
/// the nonce is derived from the secret, the tx hash, and a retry counter
/// (resampled until `R = (k0 + t)·G` has even Y — expected 2 attempts).
pub fn s2c_sign(
    kp: &NullifierKeypair,
    tx_hash: &[u8; 32],
    chain_id: &[u8; 32],
) -> (NullifierSig, S2cOpening) {
    let (sig, opening, _attempts) = s2c_sign_counted(kp, tx_hash, chain_id);
    (sig, opening)
}

/// As [`s2c_sign`], also reporting how many parity retries were needed
/// (exposed so tests can prove the resample path runs).
pub fn s2c_sign_counted(
    kp: &NullifierKeypair,
    tx_hash: &[u8; 32],
    chain_id: &[u8; 32],
) -> (NullifierSig, S2cOpening, u32) {
    let msg = nullifier_message(chain_id);
    let sk_bytes: [u8; 32] = kp.sk.to_bytes().into();
    for ctr in 0u32.. {
        let k0 = scalar_from_hash(tagged_hash(
            "SCSV/s2c-nonce",
            &[&sk_bytes, tx_hash, &msg, &ctr.to_le_bytes()],
        ));
        if k0 == Scalar::ZERO {
            continue;
        }
        let r0_point = (ProjectivePoint::GENERATOR * k0).to_affine();
        let r0 = compress33(&r0_point);
        let k = k0 + s2c_tweak(&r0, tx_hash);
        if k == Scalar::ZERO {
            continue;
        }
        let r_point = (ProjectivePoint::GENERATOR * k).to_affine();
        if bool::from(r_point.y_is_odd()) {
            continue; // resample: negating k would break the s2c opening
        }
        let rx = x_bytes(&r_point);
        let e = challenge(&rx, &kp.pk, &msg);
        let s = k + e * kp.sk;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&rx);
        sig[32..].copy_from_slice(&s.to_bytes());
        return (NullifierSig { pk: kp.pk, sig }, S2cOpening { r0 }, ctr);
    }
    unreachable!("counter space exhausted")
}

/// Plain BIP340 signature over an arbitrary 32-byte message with a
/// deterministic nonce. Used by issuers to sign records — never for
/// nullifiers, whose nonces must carry the sign-to-contract tweak.
pub fn bip340_sign(kp: &NullifierKeypair, msg32: &[u8; 32]) -> [u8; 64] {
    let sk_bytes: [u8; 32] = kp.sk.to_bytes().into();
    for ctr in 0u32.. {
        let k0 = scalar_from_hash(tagged_hash(
            "SCSV/plain-nonce",
            &[&sk_bytes, msg32, &ctr.to_le_bytes()],
        ));
        if k0 == Scalar::ZERO {
            continue;
        }
        let r_point = (ProjectivePoint::GENERATOR * k0).to_affine();
        // Plain BIP340 may negate the nonce on odd Y — no opening to preserve.
        let k = if bool::from(r_point.y_is_odd()) {
            -k0
        } else {
            k0
        };
        let rx = x_bytes(&r_point);
        let e = challenge(&rx, &kp.pk, msg32);
        let s = k + e * kp.sk;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&rx);
        sig[32..].copy_from_slice(&s.to_bytes());
        return sig;
    }
    unreachable!()
}

/// Standard BIP340 verification of `sig` over `msg32` by x-only `pk`.
pub fn bip340_verify(pk: &XOnlyBytes, msg32: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Some(p) = lift_x(pk) else { return false };
    let rx: [u8; 32] = sig[..32].try_into().unwrap();
    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(
        <[u8; 32]>::try_from(&sig[32..]).unwrap().into(),
    )) else {
        return false;
    };
    // r must be a valid x coordinate.
    let Some(_r_point) = lift_x(&rx) else {
        return false;
    };
    let e = challenge(&rx, pk, msg32);
    let r = ProjectivePoint::GENERATOR * s - ProjectivePoint::from(p) * e;
    if bool::from(r.is_identity()) {
        return false;
    }
    let r = r.to_affine();
    !bool::from(r.y_is_odd()) && x_bytes(&r) == rx
}

/// Verify a nullifier: BIP340 over the fixed message, plus the s2c opening
/// tying the nonce to `tx_hash`. This is the full native per-hop check.
pub fn s2c_verify(
    n: &NullifierSig,
    opening: &S2cOpening,
    tx_hash: &[u8; 32],
    chain_id: &[u8; 32],
) -> bool {
    let msg = nullifier_message(chain_id);
    if !bip340_verify(&n.pk, &msg, &n.sig) {
        return false;
    }
    let rx: [u8; 32] = n.sig[..32].try_into().unwrap();
    let Some(r) = lift_x(&rx) else { return false };
    let Some(r0) = decompress33(&opening.r0) else {
        return false;
    };
    let t = s2c_tweak(&opening.r0, tx_hash);
    ProjectivePoint::from(r0) + ProjectivePoint::GENERATOR * t == ProjectivePoint::from(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(n: u8) -> NullifierKeypair {
        NullifierKeypair::from_seed(&[n; 32]).unwrap()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = kp(1);
        let tx = [0xAB; 32];
        let chain = [0xCD; 32];
        let (sig, opening) = s2c_sign(&kp, &tx, &chain);
        assert!(s2c_verify(&sig, &opening, &tx, &chain));
        // Deterministic.
        let (sig2, opening2) = s2c_sign(&kp, &tx, &chain);
        assert_eq!(sig, sig2);
        assert_eq!(opening, opening2);
    }

    #[test]
    fn cross_check_against_k256_schnorr_verifier() {
        use k256::schnorr::signature::hazmat::PrehashVerifier;
        let kp = kp(2);
        let tx = [3u8; 32];
        let chain = [4u8; 32];
        let (sig, _) = s2c_sign(&kp, &tx, &chain);
        let vk = k256::schnorr::VerifyingKey::from_bytes(&sig.pk).unwrap();
        let parsed = k256::schnorr::Signature::try_from(&sig.sig[..]).unwrap();
        vk.verify_prehash(&nullifier_message(&chain), &parsed)
            .expect("upstream BIP340 verifier must accept our signature");
    }

    #[test]
    fn tamper_matrix() {
        let kp = kp(5);
        let tx = [7u8; 32];
        let chain = [8u8; 32];
        let (sig, opening) = s2c_sign(&kp, &tx, &chain);

        // Wrong tx hash: BIP340 still passes, s2c opening must fail.
        let msg = nullifier_message(&chain);
        assert!(bip340_verify(&sig.pk, &msg, &sig.sig));
        assert!(!s2c_verify(&sig, &opening, &[9u8; 32], &chain));
        // Wrong chain id: message changes, BIP340 fails.
        assert!(!s2c_verify(&sig, &opening, &tx, &[9u8; 32]));
        // Tampered s.
        let mut bad = sig;
        bad.sig[63] ^= 1;
        assert!(!s2c_verify(&bad, &opening, &tx, &chain));
        // Tampered r.
        let mut bad = sig;
        bad.sig[0] ^= 1;
        assert!(!s2c_verify(&bad, &opening, &tx, &chain));
        // Tampered opening.
        let mut bad_open = opening;
        bad_open.r0[1] ^= 1;
        assert!(!s2c_verify(&sig, &bad_open, &tx, &chain));
        // Wrong pk.
        let mut bad = sig;
        bad.pk = kp2_pk();
        assert!(!s2c_verify(&bad, &opening, &tx, &chain));
    }

    fn kp2_pk() -> XOnlyBytes {
        kp(6).pk
    }

    #[test]
    fn parity_resample_path_exercised() {
        // Over many tx hashes, both "no retry" and "at least one retry" must
        // occur — proving the even-Y resample loop actually runs.
        let kp = kp(9);
        let chain = [1u8; 32];
        let mut saw_zero = false;
        let mut saw_retry = false;
        for i in 0u32..64 {
            let mut tx = [0u8; 32];
            tx[..4].copy_from_slice(&i.to_le_bytes());
            let (sig, opening, attempts) = s2c_sign_counted(&kp, &tx, &chain);
            assert!(s2c_verify(&sig, &opening, &tx, &chain));
            if attempts == 0 {
                saw_zero = true;
            } else {
                saw_retry = true;
            }
            if saw_zero && saw_retry {
                return;
            }
        }
        panic!("64 signatures never exercised both parity paths");
    }

    #[test]
    fn secret_roundtrip() {
        let kp = kp(11);
        let restored = NullifierKeypair::from_secret_bytes(&kp.secret_bytes()).unwrap();
        assert_eq!(kp.pk, restored.pk);
    }
}
