//! The proof-bundle wire format (`spec/15-PROOF-BUNDLES.md`): a coin plus the
//! ancestry of transaction hops that created it. Serialized with postcard;
//! every field is bytes/integers, so no field-element serde is involved (the
//! STARK proof is postcard-serialized separately into `balance_proof`).

use serde::{Deserialize, Serialize};

use p3_field::PrimeCharacteristicRing;
use scsv_core::codec::{amount_to_limbs, bytes32_to_limbs};
use scsv_core::hash::{h_sponge, Digest, Domain};
use scsv_core::types::coin_id as core_coin_id;
use scsv_core::F;

/// A transaction location on the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loc {
    pub height: u64,
    pub tx_index: u32,
}

impl From<scsv_core::types::ChainLoc> for Loc {
    fn from(l: scsv_core::types::ChainLoc) -> Self {
        Loc {
            height: l.height,
            tx_index: l.tx_index,
        }
    }
}
impl From<Loc> for scsv_core::types::ChainLoc {
    fn from(l: Loc) -> Self {
        scsv_core::types::ChainLoc {
            height: l.height,
            tx_index: l.tx_index,
        }
    }
}

/// A coin, as carried in a bundle. `null_pk` is the nullifier public key that
/// spends this coin — committed here so a double-spend reuses it and collides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCoin {
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub addr: [u8; 32],
    pub null_pk: [u8; 32],
    pub creating_tx_hash: [u8; 32],
    pub out_index: u32,
}

impl WireCoin {
    /// `coinID = Poseidon2(creatingTxHash, outIndex)`.
    pub fn coin_id(&self) -> Digest {
        core_coin_id(&self.creating_tx_hash, self.out_index)
    }
}

/// A per-input nullifier: the published key, its BIP340 signature, the
/// sign-to-contract opening, and where it landed on the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireNullifier {
    pub pk: [u8; 32],
    #[serde(with = "fixed_bytes")]
    pub sig: [u8; 64],
    #[serde(with = "fixed_bytes")]
    pub s2c_r0: [u8; 33],
    pub loc: Loc,
}

/// serde adapter for fixed byte arrays larger than 32 (serde derives arrays only
/// up to length 32). Serializes exactly as serde's built-in array impl — a
/// fixed-length tuple — so postcard writes the raw bytes with no length prefix.
mod fixed_bytes {
    use core::fmt;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        arr: &[u8; N],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let mut t = ser.serialize_tuple(N)?;
        for b in arr {
            t.serialize_element(b)?;
        }
        t.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        de: D,
    ) -> Result<[u8; N], D::Error> {
        struct ArrVisitor<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for ArrVisitor<N> {
            type Value = [u8; N];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "an array of {N} bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; N], A::Error> {
                let mut out = [0u8; N];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        de.deserialize_tuple(N, ArrVisitor::<N>)
    }
}

/// One transaction hop in a coin's ancestry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireHop {
    pub tx_hash: [u8; 32],
    pub asset_id: [u8; 32],
    /// Disambiguates transactions that would otherwise share an essence (mints
    /// have no inputs; the issuer uses the record sequence). Transfers use 0.
    pub salt: u64,
    pub is_mint: bool,
    pub inputs: Vec<WireCoin>,
    pub outputs: Vec<WireCoin>,
    /// One nullifier per input (empty for a mint).
    pub nullifiers: Vec<WireNullifier>,
    /// For a mint hop: where the MINT record was published.
    pub mint_record_loc: Option<Loc>,
    /// A postcard-serialized transfer balance/range STARK proof (empty for a
    /// mint, whose authority is the on-chain issuer record).
    pub balance_proof: Vec<u8>,
}

/// A coin plus its full deduplicated ancestry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinBundle {
    pub chain_id: [u8; 32],
    pub hops: Vec<WireHop>,
    pub target_tx_hash: [u8; 32],
    pub target_out_index: u32,
}

impl CoinBundle {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("serialize bundle")
    }
    pub fn from_bytes(b: &[u8]) -> Option<CoinBundle> {
        postcard::from_bytes(b).ok()
    }

    /// The target coin, if present.
    pub fn target(&self) -> Option<&WireCoin> {
        self.hops
            .iter()
            .find(|h| h.tx_hash == self.target_tx_hash)
            .and_then(|h| {
                h.outputs
                    .iter()
                    .find(|c| c.out_index == self.target_out_index)
            })
    }
}

/// The canonical transaction-essence hash: binds a hop to its inputs and its
/// outputs' value/recipient data (NOT the outputs' creating-tx-hash, which *is*
/// this value). Both the builder and the verifier compute it identically.
pub fn essence_tx_hash(
    salt: u64,
    is_mint: bool,
    asset_id: &[u8; 32],
    input_coin_ids: &[Digest],
    outputs: &[OutputEssence],
) -> [u8; 32] {
    let mut input: Vec<F> = Vec::new();
    input.extend_from_slice(&scsv_core::codec::u64_to_limbs16(salt));
    input.push(F::from_bool(is_mint));
    input.extend_from_slice(&bytes32_to_limbs(asset_id));
    input.push(F::from_u32(input_coin_ids.len() as u32));
    for cid in input_coin_ids {
        input.extend_from_slice(&cid.0);
    }
    input.push(F::from_u32(outputs.len() as u32));
    for o in outputs {
        input.extend_from_slice(&bytes32_to_limbs(&o.asset_id));
        input.extend_from_slice(&amount_to_limbs(o.amount));
        input.extend_from_slice(&bytes32_to_limbs(&o.addr));
        input.extend_from_slice(&bytes32_to_limbs(&o.null_pk));
    }
    h_sponge(Domain::TxEssence, &input).to_bytes()
}

/// The value/recipient data of one output, for the essence hash.
pub struct OutputEssence {
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub addr: [u8; 32],
    pub null_pk: [u8; 32],
}

impl From<&WireCoin> for OutputEssence {
    fn from(c: &WireCoin) -> Self {
        OutputEssence {
            asset_id: c.asset_id,
            amount: c.amount,
            addr: c.addr,
            null_pk: c.null_pk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(seed: u8, amount: u64) -> WireCoin {
        WireCoin {
            asset_id: [seed; 32],
            amount,
            addr: [seed.wrapping_add(1); 32],
            null_pk: [seed.wrapping_add(2); 32],
            creating_tx_hash: [seed.wrapping_add(3); 32],
            out_index: 0,
        }
    }

    #[test]
    fn bundle_roundtrip() {
        let hop = WireHop {
            tx_hash: [9; 32],
            asset_id: [1; 32],
            salt: 7,
            is_mint: true,
            inputs: vec![],
            outputs: vec![coin(5, 1000)],
            nullifiers: vec![],
            mint_record_loc: Some(Loc {
                height: 3,
                tx_index: 0,
            }),
            balance_proof: vec![],
        };
        let bundle = CoinBundle {
            chain_id: [0xAB; 32],
            hops: vec![hop],
            target_tx_hash: [9; 32],
            target_out_index: 0,
        };
        assert_eq!(CoinBundle::from_bytes(&bundle.to_bytes()).unwrap(), bundle);
        assert_eq!(bundle.target().unwrap().amount, 1000);
    }

    #[test]
    fn essence_binds_inputs_and_outputs() {
        let o = OutputEssence {
            asset_id: [1; 32],
            amount: 5,
            addr: [2; 32],
            null_pk: [3; 32],
        };
        let h1 = essence_tx_hash(0, false, &[1; 32], &[Digest::ZERO], &[o]);
        let o2 = OutputEssence {
            asset_id: [1; 32],
            amount: 6,
            addr: [2; 32],
            null_pk: [3; 32],
        };
        let h2 = essence_tx_hash(0, false, &[1; 32], &[Digest::ZERO], &[o2]);
        assert_ne!(h1, h2, "amount change changes tx hash");
    }
}
