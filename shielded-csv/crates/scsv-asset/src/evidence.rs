//! Off-chain evidence for provable burns and seizures (`spec/11-BURNS.md`,
//! `spec/13-SEIZURE.md`).
//!
//! Records carry only a 32-byte hash; the evidence itself is hosted off-chain
//! and resolved through an [`EvidenceStore`]. A burn or seizure counts toward
//! supply reduction only when its evidence is available and verifies against
//! the record — otherwise the audit stays conservative-high.

use scsv_core::codec::bytes_to_limbs16;
use scsv_core::hash::{h_sponge, Digest, Domain};

/// Resolves a 32-byte evidence hash to its bytes, if available.
pub trait EvidenceStore {
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>>;
}

/// A burn proof: the destroyed coin's disclosed amount and asset, plus the
/// spent coin's identity. In v1 this discloses the coin and its amount and
/// binds them to the asset; the on-chain nullifier (referenced by the BURN
/// record) is what proves the coin was actually spent. The full "destroyed and
/// unspendable" STARK statement is the recursion-era upgrade (spec/99).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnProof {
    pub asset_id: Digest,
    pub amount: u64,
    pub coin_id: Digest,
}

impl BurnProof {
    /// Canonical bytes: assetId(32) | amount LE(8) | coinId(32).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72);
        out.extend_from_slice(&self.asset_id.to_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.coin_id.to_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<BurnProof> {
        if b.len() != 72 {
            return None;
        }
        Some(BurnProof {
            asset_id: Digest::from_bytes(&b[..32].try_into().unwrap())?,
            amount: u64::from_le_bytes(b[32..40].try_into().unwrap()),
            coin_id: Digest::from_bytes(&b[40..72].try_into().unwrap())?,
        })
    }

    /// The content-addressing hash committed by the BURN record.
    pub fn hash(&self) -> [u8; 32] {
        h_sponge(Domain::Bundle, &bytes_to_limbs16(&self.to_bytes())).to_bytes()
    }
}

/// A seizure evidence pack: the seized coin's disclosed amount and identity,
/// supplied by whoever reported/froze it. Structurally identical to a burn
/// proof (both disclose a coin's amount and asset), but semantically it applies
/// to a frozen handle (`spec/13-SEIZURE.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeizeEvidence {
    pub asset_id: Digest,
    pub amount: u64,
    pub coin_id: Digest,
}

impl SeizeEvidence {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72);
        out.extend_from_slice(&self.asset_id.to_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.coin_id.to_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<SeizeEvidence> {
        BurnProof::from_bytes(b).map(|p| SeizeEvidence {
            asset_id: p.asset_id,
            amount: p.amount,
            coin_id: p.coin_id,
        })
    }

    /// The content-addressing hash committed by the SEIZE record.
    pub fn hash(&self) -> [u8; 32] {
        h_sponge(Domain::Bundle, &bytes_to_limbs16(&self.to_bytes())).to_bytes()
    }
}

/// The off-chain contents of a FREEZE-UPDATE: which handles were added to and
/// removed from the frozen set (`spec/12-FREEZE.md`). Committed by the record's
/// `delta_hash`; an issuer that stops serving these bricks its own asset's
/// spendability, which forces availability.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FreezeDelta {
    pub added: Vec<Digest>,
    pub removed: Vec<Digest>,
}

impl FreezeDelta {
    /// Canonical bytes: u32 count added, each 32B; u32 count removed, each 32B.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.added.len() as u32).to_le_bytes());
        for d in &self.added {
            out.extend_from_slice(&d.to_bytes());
        }
        out.extend_from_slice(&(self.removed.len() as u32).to_le_bytes());
        for d in &self.removed {
            out.extend_from_slice(&d.to_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<FreezeDelta> {
        let mut r = b;
        let take_digests = |r: &mut &[u8]| -> Option<Vec<Digest>> {
            if r.len() < 4 {
                return None;
            }
            let n = u32::from_le_bytes(r[..4].try_into().unwrap()) as usize;
            *r = &r[4..];
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                if r.len() < 32 {
                    return None;
                }
                v.push(Digest::from_bytes(&r[..32].try_into().unwrap())?);
                *r = &r[32..];
            }
            Some(v)
        };
        let added = take_digests(&mut r)?;
        let removed = take_digests(&mut r)?;
        if !r.is_empty() {
            return None;
        }
        Some(FreezeDelta { added, removed })
    }

    pub fn hash(&self) -> [u8; 32] {
        h_sponge(Domain::Bundle, &bytes_to_limbs16(&self.to_bytes())).to_bytes()
    }
}

/// An in-memory evidence store, keyed by content hash. Used by tests, demos,
/// and as the wallet's local cache; a production issuer would serve these over
/// HTTP.
#[derive(Clone, Debug, Default)]
pub struct MemoryEvidence {
    map: std::collections::HashMap<[u8; 32], Vec<u8>>,
}

impl MemoryEvidence {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a blob under its content hash, returning that hash.
    pub fn insert(&mut self, hash: [u8; 32], bytes: Vec<u8>) {
        self.map.insert(hash, bytes);
    }

    pub fn put_burn(&mut self, p: &BurnProof) -> [u8; 32] {
        let h = p.hash();
        self.map.insert(h, p.to_bytes());
        h
    }

    pub fn put_seize(&mut self, e: &SeizeEvidence) -> [u8; 32] {
        let h = e.hash();
        self.map.insert(h, e.to_bytes());
        h
    }

    pub fn put_delta(&mut self, d: &FreezeDelta) -> [u8; 32] {
        let h = d.hash();
        self.map.insert(h, d.to_bytes());
        h
    }
}

impl EvidenceStore for MemoryEvidence {
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.map.get(hash).cloned()
    }
}

/// An evidence store that resolves nothing — models withheld evidence, driving
/// the audit conservative-high.
pub struct NoEvidence;
impl EvidenceStore for NoEvidence {
    fn get(&self, _hash: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use scsv_core::F;

    #[test]
    fn burn_proof_roundtrip_and_hash_binding() {
        let p = BurnProof {
            asset_id: Digest([F::from_u32(3); 8]),
            amount: 12345,
            coin_id: Digest([F::from_u32(7); 8]),
        };
        assert_eq!(BurnProof::from_bytes(&p.to_bytes()).unwrap(), p);
        // The hash binds every field.
        let mut p2 = p.clone();
        p2.amount += 1;
        assert_ne!(p.hash(), p2.hash());
    }

    #[test]
    fn memory_store_resolves_by_hash() {
        let mut store = MemoryEvidence::new();
        let p = BurnProof {
            asset_id: Digest([F::ONE; 8]),
            amount: 9,
            coin_id: Digest([F::from_u32(2); 8]),
        };
        let h = store.put_burn(&p);
        assert_eq!(BurnProof::from_bytes(&store.get(&h).unwrap()).unwrap(), p);
        assert!(store.get(&[0u8; 32]).is_none());
    }
}
