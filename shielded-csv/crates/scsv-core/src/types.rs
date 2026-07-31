//! Protocol data types with canonical byte layouts and derived identifiers.
//! See `spec/02-KEYS-ACCOUNTS.md`, `spec/03-COINS.md`, `spec/04-STATE.md`,
//! `spec/09-ISSUANCE.md`.
//!
//! Canonical encodings are hand-rolled byte layouts — never serde — so hashes
//! over them are layout-stable. Every `canonical_bytes` here is a consensus
//! surface: changing one changes derived identifiers.

use crate::codec::{amount_to_limbs, bytes32_to_limbs, bytes_to_limbs16, u64_to_limbs16};
use crate::hash::{h_sponge, Digest, Domain};
use crate::F;

/// x-only secp256k1 public key bytes (BIP340).
pub type XOnlyBytes = [u8; 32];
/// A transaction essence hash (`Domain::TxEssence` digest bytes).
pub type TxHash = [u8; 32];

/// Where a payload landed on the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainLoc {
    pub height: u64,
    pub tx_index: u32,
}

/// Asset policy fixed at genesis (`spec/09-ISSUANCE.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub public_supply: bool,
    pub freezable: bool,
    /// 0 = unbounded.
    pub max_supply: u64,
    pub decimals: u8,
}

impl Policy {
    pub fn flags_byte(&self) -> u8 {
        (self.public_supply as u8) | ((self.freezable as u8) << 1)
    }

    /// The packed policy-bits public input (`spec/14-AIR-STATEMENT.md`).
    pub fn bits_field(&self) -> F {
        crate::field::f_from_u32(self.flags_byte() as u32)
    }
}

/// Maximum byte length of each genesis string field.
pub const MAX_GENESIS_STRING: usize = 128;

/// Asset genesis (`spec/09-ISSUANCE.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    pub version: u8,
    pub issuer_pk: XOnlyBytes,
    /// Poseidon2 hash of the shielded-mint authority secret; MUST be zero when
    /// `policy.public_supply` (enforced natively here and in-circuit, S4).
    pub mint_auth_key_hash: Digest,
    pub policy: Policy,
    pub ticker: String,
    pub name: String,
    pub uri: String,
    pub extended_metadata_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenesisError {
    #[error("public-supply asset must have zero mintAuthKeyHash")]
    PublicSupplyWithMintKey,
    #[error("string field `{0}` exceeds {MAX_GENESIS_STRING} bytes")]
    StringTooLong(&'static str),
    #[error("unsupported genesis version {0}")]
    BadVersion(u8),
}

impl Genesis {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), GenesisError> {
        if self.version != Self::VERSION {
            return Err(GenesisError::BadVersion(self.version));
        }
        if self.policy.public_supply && !self.mint_auth_key_hash.is_zero() {
            return Err(GenesisError::PublicSupplyWithMintKey);
        }
        for (field, s) in [
            ("ticker", &self.ticker),
            ("name", &self.name),
            ("uri", &self.uri),
        ] {
            if s.len() > MAX_GENESIS_STRING {
                return Err(GenesisError::StringTooLong(field));
            }
        }
        Ok(())
    }

    /// Canonical layout: version | issuerPk | mintAuthKeyHash | flags |
    /// maxSupply LE | decimals | (len16 + bytes) x ticker,name,uri | extHash.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(128 + self.ticker.len() + self.name.len() + self.uri.len());
        out.push(self.version);
        out.extend_from_slice(&self.issuer_pk);
        out.extend_from_slice(&self.mint_auth_key_hash.to_bytes());
        out.push(self.policy.flags_byte());
        out.extend_from_slice(&self.policy.max_supply.to_le_bytes());
        out.push(self.policy.decimals);
        for s in [&self.ticker, &self.name, &self.uri] {
            out.extend_from_slice(&(s.len() as u16).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&self.extended_metadata_hash);
        out
    }

    /// `assetId = h_sponge(GenesisH, 16-bit limbs of canonical bytes)`.
    pub fn asset_id(&self) -> Digest {
        h_sponge(Domain::GenesisH, &bytes_to_limbs16(&self.canonical_bytes()))
    }

    /// Strict decode of [`Self::canonical_bytes`].
    pub fn from_canonical_bytes(b: &[u8]) -> Option<Genesis> {
        let mut r = Reader(b);
        let version = r.u8()?;
        let issuer_pk: [u8; 32] = r.array()?;
        let mint_auth_key_hash = Digest::from_bytes(&r.array()?)?;
        let flags = r.u8()?;
        if flags & !0b11 != 0 {
            return None;
        }
        let max_supply = u64::from_le_bytes(r.array()?);
        let decimals = r.u8()?;
        let mut strings = Vec::with_capacity(3);
        for _ in 0..3 {
            let len = u16::from_le_bytes(r.array()?) as usize;
            let s = String::from_utf8(r.take(len)?.to_vec()).ok()?;
            strings.push(s);
        }
        let extended_metadata_hash: [u8; 32] = r.array()?;
        if !r.0.is_empty() {
            return None;
        }
        let uri = strings.pop()?;
        let name = strings.pop()?;
        let ticker = strings.pop()?;
        Some(Genesis {
            version,
            issuer_pk,
            mint_auth_key_hash,
            policy: Policy {
                public_supply: flags & 1 != 0,
                freezable: flags & 2 != 0,
                max_supply,
                decimals,
            },
            ticker,
            name,
            uri,
            extended_metadata_hash,
        })
    }
}

/// Minimal strict byte reader.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (x, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*x)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (x, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(x)
    }
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).map(|s| s.try_into().unwrap())
    }
}

/// Account state (`spec/04-STATE.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountState {
    pub account_id: Digest,
    pub nullifier_pk_hash: Digest,
    pub spent_root: Digest,
    pub balances_root: Digest,
    pub seq: u64,
}

impl AccountState {
    pub fn commitment(&self) -> Digest {
        let mut input = Vec::with_capacity(36);
        input.extend_from_slice(&self.account_id.0);
        input.extend_from_slice(&self.nullifier_pk_hash.0);
        input.extend_from_slice(&self.spent_root.0);
        input.extend_from_slice(&self.balances_root.0);
        input.extend_from_slice(&u64_to_limbs16(self.seq));
        h_sponge(Domain::StateCom, &input)
    }
}

/// A coin (`spec/03-COINS.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub asset_id: Digest,
    pub amount: u64,
    pub addr: Digest,
    pub creating_tx_hash: TxHash,
    pub out_index: u32,
    pub nullifier_loc: ChainLoc,
}

impl Coin {
    pub fn coin_id(&self) -> Digest {
        coin_id(&self.creating_tx_hash, self.out_index)
    }
}

/// Maximum outputs per transaction (`spec/05-TRANSACTIONS.md`); bounds
/// `out_index` so its limb is always canonical.
pub const MAX_OUTPUTS: u32 = 8;

/// `coinID = h_sponge(CoinId, txHash limbs ‖ outIndex)`.
///
/// Panics if `out_index >= MAX_OUTPUTS` — a truncated index would alias coin
/// identities, so this is a hard protocol bound, not a mask.
pub fn coin_id(creating_tx_hash: &TxHash, out_index: u32) -> Digest {
    assert!(
        out_index < MAX_OUTPUTS,
        "out_index {out_index} >= {MAX_OUTPUTS}"
    );
    let mut input = Vec::with_capacity(17);
    input.extend_from_slice(&bytes32_to_limbs(creating_tx_hash));
    input.push(crate::field::f_from_u32(out_index));
    h_sponge(Domain::CoinId, &input)
}

/// Output-leaf hash inside an outputs commitment (S7: fresh `leaf_r` per leaf).
pub fn output_leaf_hash(asset_id: &Digest, amount: u64, addr: &Digest, leaf_r: &Digest) -> Digest {
    let mut input = Vec::with_capacity(27);
    input.extend_from_slice(&asset_id.0);
    input.extend_from_slice(&amount_to_limbs(amount));
    input.extend_from_slice(&addr.0);
    input.extend_from_slice(&leaf_r.0);
    h_sponge(Domain::CoinLeaf, &input)
}

/// `accountID = h_sponge(AccountId, accountSk ‖ firstNullifierPkHash)` (S1).
pub fn account_id(account_sk: &Digest, first_nullifier_pk_hash: &Digest) -> Digest {
    let mut input = [F::ZERO; 16];
    input[..8].copy_from_slice(&account_sk.0);
    input[8..].copy_from_slice(&first_nullifier_pk_hash.0);
    h_sponge(Domain::AccountId, &input)
}

/// `addr = h_sponge(Addr, accountID ‖ addr_r)`.
pub fn address(account_id: &Digest, addr_r: &Digest) -> Digest {
    let mut input = [F::ZERO; 16];
    input[..8].copy_from_slice(&account_id.0);
    input[8..].copy_from_slice(&addr_r.0);
    h_sponge(Domain::Addr, &input)
}

/// Hash of an on-chain nullifier public key, as held in account state.
pub fn nullifier_pk_hash(pk: &XOnlyBytes) -> Digest {
    h_sponge(Domain::NullifierPk, &bytes32_to_limbs(pk))
}

use p3_field::PrimeCharacteristicRing;

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> Genesis {
        Genesis {
            version: 1,
            issuer_pk: [7u8; 32],
            mint_auth_key_hash: Digest::ZERO,
            policy: Policy {
                public_supply: true,
                freezable: true,
                max_supply: 100_000_000_000_000,
                decimals: 6,
            },
            ticker: "USDS".into(),
            name: "US Dollar Shielded".into(),
            uri: "https://issuer.example/scsv".into(),
            extended_metadata_hash: [9u8; 32],
        }
    }

    #[test]
    fn genesis_roundtrip_and_id_stability() {
        let g = genesis();
        g.validate().unwrap();
        let bytes = g.canonical_bytes();
        let g2 = Genesis::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(g, g2);
        assert_eq!(g.asset_id(), g2.asset_id());
        // Any field change changes the assetId.
        let mut g3 = g.clone();
        g3.policy.freezable = false;
        assert_ne!(g.asset_id(), g3.asset_id());
        let mut g4 = g.clone();
        g4.ticker = "USDT".into();
        assert_ne!(g.asset_id(), g4.asset_id());
    }

    #[test]
    fn public_supply_requires_zero_mint_key() {
        let mut g = genesis();
        g.mint_auth_key_hash = h_sponge(Domain::NullifierPk, &[F::ONE]);
        assert_eq!(g.validate(), Err(GenesisError::PublicSupplyWithMintKey));
        g.policy.public_supply = false;
        g.validate().unwrap();
    }

    #[test]
    fn genesis_decode_rejects_trailing_and_bad_flags() {
        let g = genesis();
        let mut b = g.canonical_bytes();
        b.push(0);
        assert!(Genesis::from_canonical_bytes(&b).is_none());
        let mut b = g.canonical_bytes();
        b[65] |= 0b100; // undefined flag bit
        assert!(Genesis::from_canonical_bytes(&b).is_none());
    }

    #[test]
    fn state_commitment_binds_every_field() {
        let base = AccountState {
            account_id: h_sponge(Domain::AccountId, &[F::ONE]),
            nullifier_pk_hash: h_sponge(Domain::NullifierPk, &[F::ONE]),
            spent_root: Digest::ZERO,
            balances_root: Digest::ZERO,
            seq: 3,
        };
        let c = base.commitment();
        for delta in 0..5 {
            let mut s = base;
            match delta {
                0 => s.account_id = Digest::ZERO,
                1 => s.nullifier_pk_hash = Digest::ZERO,
                2 => s.spent_root = h_sponge(Domain::StateCom, &[]),
                3 => s.balances_root = h_sponge(Domain::StateCom, &[]),
                _ => s.seq = 4,
            }
            assert_ne!(s.commitment(), c, "field {delta} not bound");
        }
    }

    #[test]
    fn coin_id_binds_tx_and_index() {
        let a = coin_id(&[1u8; 32], 0);
        let b = coin_id(&[1u8; 32], 1);
        let c = coin_id(&[2u8; 32], 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
