//! The STARK field: BabyBear (`p = 2^31 - 2^27 + 1`).
//!
//! All in-circuit values live here. 256-bit external objects (secp256k1
//! x-only keys, Bitcoin txids) are represented as fixed limb arrays elsewhere;
//! this module only fixes the field itself and the small helpers every crate
//! needs.

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

/// The STARK field element type used throughout Shielded CSV.
pub type F = BabyBear;

/// BabyBear modulus, `2^31 - 2^27 + 1`.
pub const P: u32 = 0x7800_0001;

/// Convert a `u32 < P` to a field element.
#[inline]
pub fn f_from_u32(x: u32) -> F {
    debug_assert!(x < P, "value {x} not in canonical range [0, P)");
    F::from_u32(x)
}

/// Canonical `u32` representative of a field element, in `[0, P)`.
#[inline]
pub fn f_to_u32(x: F) -> u32 {
    x.as_canonical_u32()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn modulus_matches() {
        assert_eq!(P, (1u32 << 31) - (1u32 << 27) + 1);
    }

    #[test]
    fn roundtrip_u32() {
        for x in [0u32, 1, 2, 1000, P - 1] {
            assert_eq!(f_to_u32(f_from_u32(x)), x);
        }
    }

    #[test]
    fn field_arithmetic_wraps_at_p() {
        // (P-1) + 1 == 0 in the field.
        let a = f_from_u32(P - 1);
        assert_eq!(a + F::ONE, F::ZERO);
    }
}
