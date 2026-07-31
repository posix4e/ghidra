//! Trace generation and the prove/verify wrapper for [`TransferBalanceAir`].
//!
//! The wrapper owns construction of the public-input vector, so a proof and its
//! verification always agree on the public inputs (soundness item S2: the
//! underlying uni-stark already observes every public value into the transcript,
//! audited at M1 — the wrapper removes the remaining foot-gun of a caller
//! passing mismatched inputs).

use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify, Proof, VerificationError};

use p3_field::PrimeCharacteristicRing;
use scsv_core::codec::amount_to_limbs; // not used for AIR limbs; see note
use scsv_core::F;

use crate::config::{config, ScsvConfig};
use crate::transfer_air::{
    TransferBalanceAir, CARRY_BOUND, CARRY_OFFSET, CARRY_SHIFT_BITS, LIMBS, LIMB_BITS, NUM_COLS,
    SLOTS,
};

/// A single amount slot in a transfer.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    pub amount: u64,
    pub is_out: bool,
}

/// The public statement a transfer proof establishes: the per-limb input and
/// output sums (which the wallet cross-checks against real coins).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPublic {
    pub in_sum: [F; LIMBS],
    pub out_sum: [F; LIMBS],
}

impl TransferPublic {
    pub fn to_vec(&self) -> Vec<F> {
        let mut v = Vec::with_capacity(2 * LIMBS);
        v.extend_from_slice(&self.in_sum);
        v.extend_from_slice(&self.out_sum);
        v
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("too many slots: {0} > {SLOTS}")]
    TooManySlots(usize),
    #[error("inputs and outputs do not conserve value")]
    NotBalanced,
    #[error("verification failed: {0}")]
    Verify(String),
}

fn amount_to_u16_limbs(x: u64) -> [u32; LIMBS] {
    core::array::from_fn(|k| ((x >> (LIMB_BITS * k)) & 0xFFFF) as u32)
}

/// Build the execution trace and the public statement for a set of slots.
pub fn build_trace(slots: &[Slot]) -> Result<(RowMajorMatrix<F>, TransferPublic), TransferError> {
    if slots.len() > SLOTS {
        return Err(TransferError::TooManySlots(slots.len()));
    }

    let mut values = F::zero_vec(SLOTS * NUM_COLS);
    let mut in_acc = [0u64; LIMBS];
    let mut out_acc = [0u64; LIMBS];

    for row in 0..SLOTS {
        let base = row * NUM_COLS;
        let (active, is_out, amount) = match slots.get(row) {
            Some(s) => (true, s.is_out, s.amount),
            None => (false, false, 0),
        };
        let limbs = amount_to_u16_limbs(amount);
        if active {
            for k in 0..LIMBS {
                if is_out {
                    out_acc[k] += limbs[k] as u64;
                } else {
                    in_acc[k] += limbs[k] as u64;
                }
            }
        }

        // Column offsets mirror the repr(C) struct order in transfer_air.rs.
        let mut c = base;
        values[c] = F::from_bool(active);
        c += 1;
        values[c] = F::from_bool(is_out);
        c += 1;
        for k in 0..LIMBS {
            values[c + k] = F::from_u32(limbs[k]);
        }
        c += LIMBS;
        for k in 0..LIMBS {
            for j in 0..LIMB_BITS {
                values[c + k * LIMB_BITS + j] = F::from_u32((limbs[k] >> j) & 1);
            }
        }
        c += LIMBS * LIMB_BITS;
        for k in 0..LIMBS {
            values[c + k] = F::from_u64(in_acc[k]);
        }
        c += LIMBS;
        for k in 0..LIMBS {
            values[c + k] = F::from_u64(out_acc[k]);
        }
        c += LIMBS;
        // carry columns filled only for the last row, below.
        let _ = c;
    }

    // Compute signed carries for the last row: in[k] + c_{k-1} - out[k] = c_k·2^16.
    let mut carries = [0i64; LIMBS];
    let mut carry_in = 0i64;
    for k in 0..LIMBS {
        let numer = in_acc[k] as i64 + carry_in - out_acc[k] as i64;
        if numer % (1 << LIMB_BITS) != 0 {
            return Err(TransferError::NotBalanced);
        }
        let c = numer / (1 << LIMB_BITS);
        if c.abs() > CARRY_BOUND {
            return Err(TransferError::NotBalanced);
        }
        carries[k] = c;
        carry_in = c;
    }
    if carry_in != 0 {
        return Err(TransferError::NotBalanced);
    }

    // Write carries and their shifted-bit decompositions into the last row.
    let last_base = (SLOTS - 1) * NUM_COLS;
    let carry_off = last_base + 2 + LIMBS + LIMBS * LIMB_BITS + LIMBS + LIMBS;
    let carry_bits_off = carry_off + LIMBS;
    for k in 0..LIMBS {
        values[carry_off + k] = if carries[k] >= 0 {
            F::from_u32(carries[k] as u32)
        } else {
            -F::from_u32((-carries[k]) as u32)
        };
        let shifted = (carries[k] + CARRY_OFFSET as i64) as u32;
        for j in 0..CARRY_SHIFT_BITS {
            values[carry_bits_off + k * CARRY_SHIFT_BITS + j] = F::from_u32((shifted >> j) & 1);
        }
    }

    let public = TransferPublic {
        in_sum: core::array::from_fn(|k| F::from_u64(in_acc[k])),
        out_sum: core::array::from_fn(|k| F::from_u64(out_acc[k])),
    };
    Ok((RowMajorMatrix::new(values, NUM_COLS), public))
}

/// Prove a transfer balances. Returns the proof and the public statement.
pub fn prove_transfer(
    slots: &[Slot],
) -> Result<(Proof<ScsvConfig>, TransferPublic), TransferError> {
    let (trace, public) = build_trace(slots)?;
    let cfg = config();
    let proof = prove(&cfg, &TransferBalanceAir, trace, &public.to_vec());
    Ok((proof, public))
}

/// Verify a transfer proof against a public statement.
pub fn verify_transfer(
    proof: &Proof<ScsvConfig>,
    public: &TransferPublic,
) -> Result<(), VerificationError<impl core::fmt::Debug>> {
    let cfg = config();
    verify(&cfg, &TransferBalanceAir, proof, &public.to_vec())
}

// `amount_to_limbs` (30/30/4) is the hashing encoding; the AIR uses 16-bit
// limbs internally for field-safe accumulation. Keep the import referenced so
// the relationship is visible and checked.
#[allow(dead_code)]
fn _encoding_note(x: u64) -> [F; 3] {
    amount_to_limbs(x)
}
