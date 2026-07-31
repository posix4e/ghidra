//! Canonical limb codecs between external byte objects and BabyBear elements.
//!
//! - 64-bit amounts split `30 + 30 + 4` bits into 3 limbs (`spec/01-CRYPTO.md`).
//!   (31-bit limbs would NOT fit: BabyBear's modulus is `2^31 - 2^27 + 1`, so
//!   values in `[P, 2^31)` are unrepresentable.)
//! - 256-bit objects (x-only keys, txids) split into 16 little-endian 16-bit
//!   limbs.
//!
//! Every encoding here is bijective on its declared domain and has a strict
//! decoder that rejects out-of-range limbs, so a malicious peer cannot smuggle
//! non-canonical encodings into hashed or proven data.

use crate::field::{f_from_u32, f_to_u32, F};

/// Errors from strict decoding.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("limb {index} out of range: {value} >= 2^{bits}")]
    LimbOutOfRange { index: usize, value: u32, bits: u32 },
}

/// A `u64` amount as 3 limbs: bits `[0,30)`, `[30,60)`, `[60,64)`.
pub type AmountLimbs = [F; 3];

/// Encode a `u64` into `30+30+4` limbs.
pub fn amount_to_limbs(x: u64) -> AmountLimbs {
    [
        f_from_u32((x & 0x3FFF_FFFF) as u32),
        f_from_u32(((x >> 30) & 0x3FFF_FFFF) as u32),
        f_from_u32((x >> 60) as u32),
    ]
}

/// Strictly decode 3 limbs back to a `u64`.
pub fn amount_from_limbs(l: &AmountLimbs) -> Result<u64, CodecError> {
    let a0 = f_to_u32(l[0]);
    let a1 = f_to_u32(l[1]);
    let a2 = f_to_u32(l[2]);
    if a0 >= 1 << 30 {
        return Err(CodecError::LimbOutOfRange {
            index: 0,
            value: a0,
            bits: 30,
        });
    }
    if a1 >= 1 << 30 {
        return Err(CodecError::LimbOutOfRange {
            index: 1,
            value: a1,
            bits: 30,
        });
    }
    if a2 >= 1 << 4 {
        return Err(CodecError::LimbOutOfRange {
            index: 2,
            value: a2,
            bits: 4,
        });
    }
    Ok((a0 as u64) | ((a1 as u64) << 30) | ((a2 as u64) << 60))
}

/// A 256-bit external object as 16 little-endian 16-bit limbs.
pub type Limbs256 = [F; 16];

/// Encode 32 bytes into 16 LE 16-bit limbs (`limb[i] = b[2i] | b[2i+1] << 8`).
pub fn bytes32_to_limbs(b: &[u8; 32]) -> Limbs256 {
    core::array::from_fn(|i| f_from_u32(b[2 * i] as u32 | ((b[2 * i + 1] as u32) << 8)))
}

/// Strictly decode 16 limbs back to 32 bytes.
pub fn limbs_to_bytes32(l: &Limbs256) -> Result<[u8; 32], CodecError> {
    let mut out = [0u8; 32];
    for (i, limb) in l.iter().enumerate() {
        let v = f_to_u32(*limb);
        if v >= 1 << 16 {
            return Err(CodecError::LimbOutOfRange {
                index: i,
                value: v,
                bits: 16,
            });
        }
        out[2 * i] = (v & 0xFF) as u8;
        out[2 * i + 1] = (v >> 8) as u8;
    }
    Ok(out)
}

/// Encode arbitrary bytes as 16-bit limbs (2 bytes per limb, zero-padded).
/// Used for hashing variable-length canonical byte strings; the length is
/// bound separately by the sponge (`crate::hash`).
pub fn bytes_to_limbs16(bytes: &[u8]) -> Vec<F> {
    bytes
        .chunks(2)
        .map(|c| {
            let lo = c[0] as u32;
            let hi = if c.len() > 1 { c[1] as u32 } else { 0 };
            f_from_u32(lo | (hi << 8))
        })
        .collect()
}

/// Encode a `u64` as a single pair of limbs `(low 32 -> 2x16, high 32 -> 2x16)`.
/// Convenience for canonical byte layouts that hash whole integers.
pub fn u64_to_limbs16(x: u64) -> [F; 4] {
    let b = x.to_le_bytes();
    core::array::from_fn(|i| f_from_u32(b[2 * i] as u32 | ((b[2 * i + 1] as u32) << 8)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn amount_edges() {
        for x in [
            0u64,
            1,
            (1 << 30) - 1,
            1 << 30,
            (1 << 60) - 1,
            1 << 60,
            u64::MAX,
        ] {
            assert_eq!(amount_from_limbs(&amount_to_limbs(x)).unwrap(), x);
        }
    }

    #[test]
    fn amount_rejects_oversized_limbs() {
        let mut l = amount_to_limbs(5);
        l[0] = f_from_u32(1 << 30);
        assert!(amount_from_limbs(&l).is_err());
        let mut l = amount_to_limbs(5);
        l[2] = f_from_u32(16);
        assert!(amount_from_limbs(&l).is_err());
    }

    #[test]
    fn bytes32_roundtrip() {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i * 7 + 3) as u8;
        }
        assert_eq!(limbs_to_bytes32(&bytes32_to_limbs(&b)).unwrap(), b);
    }

    proptest! {
        #[test]
        fn amount_roundtrip(x: u64) {
            prop_assert_eq!(amount_from_limbs(&amount_to_limbs(x)).unwrap(), x);
        }

        #[test]
        fn bytes32_roundtrip_prop(b: [u8; 32]) {
            prop_assert_eq!(limbs_to_bytes32(&bytes32_to_limbs(&b)).unwrap(), b);
        }
    }
}
