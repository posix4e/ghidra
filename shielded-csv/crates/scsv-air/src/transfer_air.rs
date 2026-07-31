//! `TransferBalanceAir` — the value-conservation and range-check core of a
//! transfer, proven in-circuit at full STARK parameters. This is spec/14's
//! constraint group 6 (per-asset balance conservation) and group 14 (u64 range
//! checks) for the transfer path (no mint/burn).
//!
//! # Scope (v0, honest)
//!
//! This AIR proves, in zero knowledge:
//! - every amount slot is a valid `u64` (four 16-bit limbs, each bit-decomposed
//!   and range-checked — BabyBear is 31-bit, so a `u64` cannot be one field
//!   element and must be limbed), and
//! - the inputs and outputs conserve value exactly, as integers, via per-limb
//!   accumulation with explicit carries — no field wraparound.
//!
//! It binds the per-limb input and output sums to public inputs, so a verifier
//! learns "these committed limb-sums come from in-range amounts and balance."
//!
//! What it does NOT yet prove is the *binding of these amounts to specific
//! coins* — that requires the Poseidon2 Merkle/commitment gadget (spec/14
//! groups 1–5, 7–13), the next increment. Until then the receiver (`spec/16`)
//! enforces that binding natively. This division of labor is documented and
//! deliberate; see the crate root.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

use scsv_core::F;

/// 16-bit limbs per u64 amount.
pub const LIMBS: usize = 4;
/// Bits per limb.
pub const LIMB_BITS: usize = 16;
/// Fixed number of amount slots (rows). Each is an input, an output, or
/// inactive. Supports up to this many input+output coins per transfer.
pub const SLOTS: usize = 8;
/// Signed per-limb carry bound. A limb sum is `< SLOTS·2^16`, so the carry out
/// of a limb (which may be a borrow) lies in `[-(SLOTS+1), SLOTS+1]`.
pub const CARRY_BOUND: i64 = SLOTS as i64 + 1;
/// Offset added to a signed carry to make it non-negative before bit
/// decomposition: `carry + OFFSET ∈ [0, 2^CARRY_SHIFT_BITS)`.
pub const CARRY_OFFSET: u32 = 16;
/// Bits needed for the shifted carry (covers `[0, 31] ⊇ [7, 25]`).
pub const CARRY_SHIFT_BITS: usize = 5;

/// Column layout of one row (one amount slot).
#[repr(C)]
pub struct TransferCols<T> {
    /// 1 if this slot carries a real amount, else 0 (padding).
    pub active: T,
    /// 1 if the active slot is an output, 0 if an input.
    pub is_out: T,
    /// The slot amount as 4 little-endian 16-bit limbs.
    pub limb: [T; LIMBS],
    /// Bit decomposition of each limb (16 bits × 4 limbs).
    pub bits: [T; LIMBS * LIMB_BITS],
    /// Running per-limb sum of input amounts, inclusive of this row.
    pub in_acc: [T; LIMBS],
    /// Running per-limb sum of output amounts, inclusive of this row.
    pub out_acc: [T; LIMBS],
    /// Signed carry columns for the final per-limb conservation equation (only
    /// constrained on the last row).
    pub carry: [T; LIMBS],
    /// Bit decomposition of each shifted carry (`carry + CARRY_OFFSET`), for a
    /// low-degree signed range check (only constrained on the last row).
    pub carry_bits: [T; LIMBS * CARRY_SHIFT_BITS],
}

pub const NUM_COLS: usize =
    2 + LIMBS + LIMBS * LIMB_BITS + LIMBS + LIMBS + LIMBS + LIMBS * CARRY_SHIFT_BITS;

impl<T> Borrow<TransferCols<T>> for [T] {
    fn borrow(&self) -> &TransferCols<T> {
        debug_assert_eq!(self.len(), NUM_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<TransferCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

/// Public inputs for this AIR: the per-limb input and output sums (8 elements).
/// The verifier binds these; the wallet checks them against real coins.
pub const NUM_PUBLIC: usize = 2 * LIMBS;

pub struct TransferBalanceAir;

impl BaseAir<F> for TransferBalanceAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        // Dominant term: `active·(1-is_out)·limb` (degree 3) under the
        // `when_transition` selector (degree 1) = 4. All carry range checks are
        // bit-decomposition (degree ≤ 2·selector), well under this. Keeping the
        // max degree at 4 means the quotient degree fits within log_blowup = 3.
        Some(4)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for TransferBalanceAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();
        let local: &TransferCols<AB::Var> = local_slice.borrow();
        let next: &TransferCols<AB::Var> = next_slice.borrow();

        let two16 = || AB::Expr::from(F::from_u32(1 << LIMB_BITS));

        // --- Booleans ---
        builder.assert_bool(local.active);
        builder.assert_bool(local.is_out);
        // is_out only set for active rows.
        builder.assert_zero(local.is_out.into() * (AB::Expr::ONE - local.active.into()));
        for b in local.bits.iter() {
            builder.assert_bool(*b);
        }

        // --- Range + limb binding: limb[k] == Σ bits · 2^j (group 14) ---
        for k in 0..LIMBS {
            let mut acc = AB::Expr::ZERO;
            for j in 0..LIMB_BITS {
                acc +=
                    local.bits[k * LIMB_BITS + j].into() * AB::Expr::from(F::from_u32(1u32 << j));
            }
            builder.assert_eq(local.limb[k].into(), acc);
        }

        // Padding rows carry zero amount so accumulators are well defined.
        for k in 0..LIMBS {
            builder.assert_zero((AB::Expr::ONE - local.active.into()) * local.limb[k].into());
        }

        // Per-limb contribution of a row to the input / output sums.
        let in_contrib = |c: &TransferCols<AB::Var>, k: usize| -> AB::Expr {
            c.active.into() * (AB::Expr::ONE - c.is_out.into()) * c.limb[k].into()
        };
        let out_contrib = |c: &TransferCols<AB::Var>, k: usize| -> AB::Expr {
            c.active.into() * c.is_out.into() * c.limb[k].into()
        };

        // --- First row seeds the accumulators ---
        {
            let mut first = builder.when_first_row();
            for k in 0..LIMBS {
                first.assert_eq(local.in_acc[k].into(), in_contrib(local, k));
                first.assert_eq(local.out_acc[k].into(), out_contrib(local, k));
            }
        }

        // --- Transition accumulates into the next row ---
        {
            let mut trans = builder.when_transition();
            for k in 0..LIMBS {
                trans.assert_eq(
                    next.in_acc[k].into(),
                    local.in_acc[k].into() + in_contrib(next, k),
                );
                trans.assert_eq(
                    next.out_acc[k].into(),
                    local.out_acc[k].into() + out_contrib(next, k),
                );
            }
        }

        // --- Last row: bind public sums and prove integer conservation ---
        {
            let pis = builder.public_values();
            let in_sum: [AB::Expr; LIMBS] = core::array::from_fn(|k| pis[k].into());
            let out_sum: [AB::Expr; LIMBS] = core::array::from_fn(|k| pis[LIMBS + k].into());

            let mut last = builder.when_last_row();
            for k in 0..LIMBS {
                last.assert_eq(local.in_acc[k].into(), in_sum[k].clone());
                last.assert_eq(local.out_acc[k].into(), out_sum[k].clone());
            }

            // Conservation with signed carries: in_acc[k] + carry_in ==
            // out_acc[k] + carry[k]·2^16, carry_in = carry[k-1], top carry == 0.
            // Carries may be borrows (negative). Range-check each via bit
            // decomposition of `carry + CARRY_OFFSET` (degree 2, not a large
            // product), keeping the quotient degree within log_blowup.
            let offset = AB::Expr::from(F::from_u32(CARRY_OFFSET));
            let mut carry_in = AB::Expr::ZERO;
            for k in 0..LIMBS {
                let mut shifted = AB::Expr::ZERO;
                for j in 0..CARRY_SHIFT_BITS {
                    let bit = local.carry_bits[k * CARRY_SHIFT_BITS + j];
                    last.assert_bool(bit);
                    shifted += bit.into() * AB::Expr::from(F::from_u32(1u32 << j));
                }
                // carry[k] + OFFSET == Σ bits · 2^j  ⇒  0 ≤ carry+OFFSET < 2^5.
                last.assert_eq(local.carry[k].into() + offset.clone(), shifted);

                last.assert_eq(
                    local.in_acc[k].into() + carry_in.clone(),
                    local.out_acc[k].into() + local.carry[k].into() * two16(),
                );
                carry_in = local.carry[k].into();
            }
            // No overflow/borrow past the top limb.
            last.assert_zero(local.carry[LIMBS - 1].into());
        }
    }
}

/// Reconstruct a `u128` from four public-input limb-sum elements (native, for
/// tests and the wallet cross-check).
pub fn u128_from_limb_sums(limbs: &[F; LIMBS]) -> u128 {
    let mut v = 0u128;
    for (k, l) in limbs.iter().enumerate() {
        v += (l.as_canonical_u32() as u128) << (LIMB_BITS * k);
    }
    v
}
