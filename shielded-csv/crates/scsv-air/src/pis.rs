//! The per-hop public-input schema (`spec/14-AIR-STATEMENT.md`).
//!
//! The vector is fixed-width and ordered; the total length is derived from the
//! field widths below so it can never drift out of sync with the layout. The
//! prove/verify wrappers own construction of this vector, so a proof and its
//! verification always see the identical public inputs (the real protection
//! behind soundness item S2 — the underlying uni-stark already observes every
//! public value into the transcript, audited at M1).

use p3_field::PrimeCharacteristicRing;
use scsv_core::codec::{amount_to_limbs, bytes32_to_limbs};
use scsv_core::hash::Digest;
use scsv_core::types::TxHash;
use scsv_core::F;

// Field widths, in declaration order.
pub const W_SCHEMA: usize = 1;
pub const W_KIND: usize = 1;
pub const W_ASSET_ID: usize = 8;
pub const W_PREV_STATE: usize = 8;
pub const W_NEW_STATE: usize = 8;
pub const W_NULLIFIER_PK: usize = 16;
pub const W_TX_HASH: usize = 16;
pub const W_OUTPUTS_COM: usize = 8;
pub const W_INPUTS_DIGEST: usize = 8;
pub const W_NUM_INPUTS: usize = 1;
pub const W_NUM_OUTPUTS: usize = 1;
pub const W_RECORD_HASH: usize = 8;
pub const W_MINT_AMOUNT: usize = 3;
pub const W_BURN_AMOUNT: usize = 3;
pub const W_FROZEN_ROOT: usize = 8;
pub const W_FROZEN_HEIGHT: usize = 1;
pub const W_POLICY_BITS: usize = 1;

/// Total public-input vector length (derived; currently 100).
pub const NUM_PIS: usize = W_SCHEMA
    + W_KIND
    + W_ASSET_ID
    + W_PREV_STATE
    + W_NEW_STATE
    + W_NULLIFIER_PK
    + W_TX_HASH
    + W_OUTPUTS_COM
    + W_INPUTS_DIGEST
    + W_NUM_INPUTS
    + W_NUM_OUTPUTS
    + W_RECORD_HASH
    + W_MINT_AMOUNT
    + W_BURN_AMOUNT
    + W_FROZEN_ROOT
    + W_FROZEN_HEIGHT
    + W_POLICY_BITS;

/// The current schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Packed `kindBits` layout.
pub const KIND_IS_INIT: u32 = 1 << 0;
pub const KIND_IS_MINT: u32 = 1 << 1;
pub const KIND_IS_BURN: u32 = 1 << 2;
pub const KIND_IS_INIT_STATE: u32 = 1 << 3;

/// The public inputs for one hop proof, in a typed form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopPublicInputs {
    pub kind_bits: u32,
    pub asset_id: Digest,
    pub prev_state_com: Digest,
    pub new_state_com: Digest,
    pub nullifier_pk: [u8; 32],
    pub tx_hash: TxHash,
    pub outputs_commitment: Digest,
    pub inputs_digest: Digest,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub record_hash: Digest,
    pub mint_amount: u64,
    pub burn_amount: u64,
    pub frozen_root: Digest,
    pub frozen_root_height: u64,
    pub policy_bits: u32,
}

impl HopPublicInputs {
    pub fn is_init(&self) -> bool {
        self.kind_bits & KIND_IS_INIT != 0
    }
    pub fn is_mint(&self) -> bool {
        self.kind_bits & KIND_IS_MINT != 0
    }
    pub fn is_burn(&self) -> bool {
        self.kind_bits & KIND_IS_BURN != 0
    }
    pub fn is_init_state(&self) -> bool {
        self.kind_bits & KIND_IS_INIT_STATE != 0
    }

    /// Serialize to the ordered field-element vector consumed by the AIR.
    pub fn to_vec(&self) -> Vec<F> {
        let mut v = Vec::with_capacity(NUM_PIS);
        v.push(F::from_u32(SCHEMA_VERSION));
        v.push(F::from_u32(self.kind_bits));
        v.extend_from_slice(&self.asset_id.0);
        v.extend_from_slice(&self.prev_state_com.0);
        v.extend_from_slice(&self.new_state_com.0);
        v.extend_from_slice(&bytes32_to_limbs(&self.nullifier_pk));
        v.extend_from_slice(&bytes32_to_limbs(&self.tx_hash));
        v.extend_from_slice(&self.outputs_commitment.0);
        v.extend_from_slice(&self.inputs_digest.0);
        v.push(F::from_u32(self.num_inputs));
        v.push(F::from_u32(self.num_outputs));
        v.extend_from_slice(&self.record_hash.0);
        v.extend_from_slice(&amount_to_limbs(self.mint_amount));
        v.extend_from_slice(&amount_to_limbs(self.burn_amount));
        v.extend_from_slice(&self.frozen_root.0);
        v.push(F::from_u64(self.frozen_root_height));
        v.push(F::from_u32(self.policy_bits));
        debug_assert_eq!(v.len(), NUM_PIS);
        v
    }
}

/// Field offsets within the public-input vector (for the AIR to index).
pub mod offset {
    use super::*;
    pub const SCHEMA: usize = 0;
    pub const KIND: usize = SCHEMA + W_SCHEMA;
    pub const ASSET_ID: usize = KIND + W_KIND;
    pub const PREV_STATE: usize = ASSET_ID + W_ASSET_ID;
    pub const NEW_STATE: usize = PREV_STATE + W_PREV_STATE;
    pub const NULLIFIER_PK: usize = NEW_STATE + W_NEW_STATE;
    pub const TX_HASH: usize = NULLIFIER_PK + W_NULLIFIER_PK;
    pub const OUTPUTS_COM: usize = TX_HASH + W_TX_HASH;
    pub const INPUTS_DIGEST: usize = OUTPUTS_COM + W_OUTPUTS_COM;
    pub const NUM_INPUTS: usize = INPUTS_DIGEST + W_INPUTS_DIGEST;
    pub const NUM_OUTPUTS: usize = NUM_INPUTS + W_NUM_INPUTS;
    pub const RECORD_HASH: usize = NUM_OUTPUTS + W_NUM_OUTPUTS;
    pub const MINT_AMOUNT: usize = RECORD_HASH + W_RECORD_HASH;
    pub const BURN_AMOUNT: usize = MINT_AMOUNT + W_MINT_AMOUNT;
    pub const FROZEN_ROOT: usize = BURN_AMOUNT + W_BURN_AMOUNT;
    pub const FROZEN_HEIGHT: usize = FROZEN_ROOT + W_FROZEN_ROOT;
    pub const POLICY_BITS: usize = FROZEN_HEIGHT + W_FROZEN_HEIGHT;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_totals_100() {
        assert_eq!(NUM_PIS, 100);
        assert_eq!(offset::POLICY_BITS + W_POLICY_BITS, NUM_PIS);
    }

    #[test]
    fn to_vec_has_correct_length_and_positions() {
        let pis = HopPublicInputs {
            kind_bits: KIND_IS_MINT,
            asset_id: Digest([F::ONE; 8]),
            prev_state_com: Digest::ZERO,
            new_state_com: Digest([F::from_u32(2); 8]),
            nullifier_pk: [0xAB; 32],
            tx_hash: [0xCD; 32],
            outputs_commitment: Digest([F::from_u32(3); 8]),
            inputs_digest: Digest::ZERO,
            num_inputs: 0,
            num_outputs: 2,
            record_hash: Digest([F::from_u32(4); 8]),
            mint_amount: 1_000_000,
            burn_amount: 0,
            frozen_root: Digest::ZERO,
            frozen_root_height: 42,
            policy_bits: 0b01,
        };
        let v = pis.to_vec();
        assert_eq!(v.len(), NUM_PIS);
        assert_eq!(v[offset::SCHEMA], F::from_u32(SCHEMA_VERSION));
        assert_eq!(v[offset::KIND], F::from_u32(KIND_IS_MINT));
        assert_eq!(v[offset::NUM_OUTPUTS], F::from_u32(2));
        assert_eq!(v[offset::FROZEN_HEIGHT], F::from_u64(42));
        assert_eq!(&v[offset::ASSET_ID..offset::ASSET_ID + 8], &[F::ONE; 8]);
    }
}
