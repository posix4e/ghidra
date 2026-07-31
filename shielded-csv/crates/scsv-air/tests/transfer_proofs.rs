//! Real end-to-end STARK proofs for the transfer balance/range AIR, at full
//! FRI parameters, plus a negative test per constraint family. These exercise
//! the actual prover and verifier — no reduced parameters.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use scsv_air::config::config;
use scsv_air::transfer::{build_trace, prove_transfer, verify_transfer, Slot, TransferPublic};
use scsv_air::transfer_air::{TransferBalanceAir, LIMB_BITS, NUM_COLS, SLOTS};
use scsv_core::F;

#[test]
fn balanced_transfer_proves_and_verifies() {
    // 1_000_000 in as two coins, out as two coins — conserves.
    let slots = [
        Slot {
            amount: 600_000,
            is_out: false,
        },
        Slot {
            amount: 400_000,
            is_out: false,
        },
        Slot {
            amount: 250_000,
            is_out: true,
        },
        Slot {
            amount: 750_000,
            is_out: true,
        },
    ];
    let (proof, public) = prove_transfer(&slots).expect("prove");
    verify_transfer(&proof, &public).expect("verify");
}

#[test]
fn transfer_with_cross_limb_carries_verifies() {
    // Inputs and outputs differ in their limb decomposition so the conservation
    // carries are exercised (including a borrow).
    let slots = [
        Slot {
            amount: 0x0001_0000,
            is_out: false,
        }, // limb1 = 1
        Slot {
            amount: 0x0000_FFFF,
            is_out: true,
        }, // limb0 = 0xFFFF
        Slot {
            amount: 0x0000_0001,
            is_out: true,
        }, // limb0 = 1  → out limb0 = 0x10000
    ];
    let (proof, public) = prove_transfer(&slots).expect("prove");
    verify_transfer(&proof, &public).expect("verify");
}

#[test]
fn u64_max_amounts_verify() {
    let slots = [
        Slot {
            amount: u64::MAX,
            is_out: false,
        },
        Slot {
            amount: u64::MAX,
            is_out: true,
        },
    ];
    let (proof, public) = prove_transfer(&slots).expect("prove");
    verify_transfer(&proof, &public).expect("verify");
}

#[test]
fn unbalanced_transfer_is_rejected_at_build() {
    let slots = [
        Slot {
            amount: 100,
            is_out: false,
        },
        Slot {
            amount: 99,
            is_out: true,
        },
    ];
    assert!(build_trace(&slots).is_err(), "unbalanced must not build");
}

// --- Negative tests: mutate a valid trace per constraint family and assert the
// verifier rejects. Full prove+verify at real parameters. ---

fn valid_trace_and_public() -> (RowMajorMatrix<F>, TransferPublic) {
    let slots = [
        Slot {
            amount: 600_000,
            is_out: false,
        },
        Slot {
            amount: 400_000,
            is_out: false,
        },
        Slot {
            amount: 1_000_000,
            is_out: true,
        },
    ];
    build_trace(&slots).expect("build")
}

/// Column offset helpers mirroring the repr(C) layout.
mod col {
    use super::*;
    pub const ACTIVE: usize = 0;
    pub const IS_OUT: usize = 1;
    pub const LIMB0: usize = 2;
    pub const BITS0: usize = 2 + 4;
    pub const IN_ACC0: usize = 2 + 4 + 4 * LIMB_BITS;
    pub const OUT_ACC0: usize = IN_ACC0 + 4;
    pub const CARRY0: usize = OUT_ACC0 + 4;
    pub fn cell(row: usize, c: usize) -> usize {
        row * NUM_COLS + c
    }
}

fn expect_reject(trace: RowMajorMatrix<F>, public: &TransferPublic, why: &str) {
    let cfg = config();
    // A tampered trace either fails to prove (constraints unsatisfiable in the
    // debug builder) or produces a proof the verifier rejects. Either is a
    // rejection; a *verifying* proof of a tampered statement is the only
    // failure.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = prove(&cfg, &TransferBalanceAir, trace, &public.to_vec());
        verify(&cfg, &TransferBalanceAir, &proof, &public.to_vec())
    }));
    match result {
        Err(_) => { /* prover panicked on unsatisfiable constraints: rejected */ }
        Ok(Ok(())) => panic!("tampered trace ({why}) produced a verifying proof"),
        Ok(Err(_)) => { /* verifier rejected */ }
    }
}

#[test]
fn negative_range_check_nonboolean_bit() {
    let (mut trace, public) = valid_trace_and_public();
    // Corrupt a bit column to a non-boolean value (group 14).
    trace.values[col::cell(0, col::BITS0)] = F::from_u32(5);
    expect_reject(trace, &public, "non-boolean bit");
}

#[test]
fn negative_range_check_limb_mismatch() {
    let (mut trace, public) = valid_trace_and_public();
    // Make limb0 disagree with its bit decomposition.
    trace.values[col::cell(0, col::LIMB0)] += F::ONE;
    expect_reject(trace, &public, "limb != bits");
}

#[test]
fn negative_balance_inflated_output() {
    let (mut trace, mut public) = valid_trace_and_public();
    // Inflate the output accumulator (and public sum) on the last row so the
    // stated statement claims more out than in — conservation must fail.
    let last = SLOTS - 1;
    trace.values[col::cell(last, col::OUT_ACC0)] += F::ONE;
    public.out_sum[0] += F::ONE;
    expect_reject(trace, &public, "inflated output");
}

#[test]
fn negative_active_flag_nonboolean() {
    let (mut trace, public) = valid_trace_and_public();
    trace.values[col::cell(0, col::ACTIVE)] = F::from_u32(2);
    expect_reject(trace, &public, "non-boolean active");
}

#[test]
fn negative_is_out_on_inactive_row() {
    let (mut trace, public) = valid_trace_and_public();
    // Row 3 is padding (inactive); set is_out — violates the coupling
    // is_out·(1-active) == 0.
    let pad = SLOTS - 1; // last row is padding here (3 real slots, 8 slots)
    trace.values[col::cell(pad, col::IS_OUT)] = F::ONE;
    expect_reject(trace, &public, "is_out on inactive row");
}

#[test]
fn negative_tampered_carry() {
    let (mut trace, public) = valid_trace_and_public();
    // Corrupt the last-row carry so conservation arithmetic breaks.
    trace.values[col::cell(SLOTS - 1, col::CARRY0)] += F::ONE;
    expect_reject(trace, &public, "tampered carry");
}

#[test]
fn wrong_public_input_rejected() {
    // A valid proof verified against a different public statement must fail —
    // this is the S2 public-input binding.
    let (proof, mut public) = prove_transfer(&[
        Slot {
            amount: 500,
            is_out: false,
        },
        Slot {
            amount: 500,
            is_out: true,
        },
    ])
    .expect("prove");
    public.in_sum[0] += F::ONE;
    assert!(verify_transfer(&proof, &public).is_err(), "PI binding");
}
