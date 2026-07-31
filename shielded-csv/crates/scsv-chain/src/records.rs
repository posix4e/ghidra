//! Issuer record wire format and signatures (`spec/08-RECORDS.md`).
//!
//! Layout of a signed record:
//! `kind:u8 | assetId:32 | seq:u64 LE | prevRecordHash:32 | body | issuerSig:64`
//!
//! The GENESIS record (kind 1, seq 0, prev 0) carries the full genesis
//! canonical bytes as its body and is signed by the genesis issuer key.
//! `record_hash` (the value `prevRecordHash` links to) is the Poseidon2 sponge
//! of the *unsigned* record bytes under `Domain::Record`.

use scsv_core::codec::bytes_to_limbs16;
use scsv_core::hash::{h_sponge, Digest, Domain};
use scsv_core::types::{Genesis, XOnlyBytes};
use scsv_native_crypto::{bip340_verify, tagged_hash};

pub const REC_TAG: &str = "SCSV/rec/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    Genesis = 1,
    Mint = 2,
    Burn = 3,
    Seize = 4,
    RotateKey = 5,
    Renounce = 6,
    MetadataUpdate = 7,
    FreezeUpdate = 8,
}

impl RecordKind {
    fn from_u8(x: u8) -> Option<Self> {
        Some(match x {
            1 => Self::Genesis,
            2 => Self::Mint,
            3 => Self::Burn,
            4 => Self::Seize,
            5 => Self::RotateKey,
            6 => Self::Renounce,
            7 => Self::MetadataUpdate,
            8 => Self::FreezeUpdate,
            _ => return None,
        })
    }
}

/// Kind-specific record body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordBody {
    /// Full genesis canonical bytes (parsed form carried alongside).
    Genesis(Genesis),
    Mint {
        amount: u64,
        cumulative_supply: u64,
        nullifier_pk: XOnlyBytes,
    },
    Burn {
        amount: u64,
        cumulative_supply: u64,
        nullifier_pk: XOnlyBytes,
        burn_proof_hash: [u8; 32],
    },
    Seize {
        coin_id: Digest,
        amount: u64,
        cumulative_supply: u64,
        evidence_pack_hash: [u8; 32],
    },
    RotateKey {
        new_issuer_pk: XOnlyBytes,
    },
    Renounce,
    MetadataUpdate {
        new_extended_metadata_hash: [u8; 32],
    },
    FreezeUpdate {
        new_frozen_root: Digest,
        delta_hash: [u8; 32],
    },
}

impl RecordBody {
    pub fn kind(&self) -> RecordKind {
        match self {
            RecordBody::Genesis(_) => RecordKind::Genesis,
            RecordBody::Mint { .. } => RecordKind::Mint,
            RecordBody::Burn { .. } => RecordKind::Burn,
            RecordBody::Seize { .. } => RecordKind::Seize,
            RecordBody::RotateKey { .. } => RecordKind::RotateKey,
            RecordBody::Renounce => RecordKind::Renounce,
            RecordBody::MetadataUpdate { .. } => RecordKind::MetadataUpdate,
            RecordBody::FreezeUpdate { .. } => RecordKind::FreezeUpdate,
        }
    }
}

/// An unsigned record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub asset_id: Digest,
    pub seq: u64,
    pub prev_record_hash: Digest,
    pub body: RecordBody,
}

impl Record {
    pub fn genesis(g: &Genesis) -> Record {
        Record {
            asset_id: g.asset_id(),
            seq: 0,
            prev_record_hash: Digest::ZERO,
            body: RecordBody::Genesis(g.clone()),
        }
    }

    /// Unsigned canonical bytes (the signature is over a tagged hash of this).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.push(self.body.kind() as u8);
        out.extend_from_slice(&self.asset_id.to_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.prev_record_hash.to_bytes());
        match &self.body {
            RecordBody::Genesis(g) => out.extend_from_slice(&g.canonical_bytes()),
            RecordBody::Mint {
                amount,
                cumulative_supply,
                nullifier_pk,
            } => {
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(&cumulative_supply.to_le_bytes());
                out.extend_from_slice(nullifier_pk);
            }
            RecordBody::Burn {
                amount,
                cumulative_supply,
                nullifier_pk,
                burn_proof_hash,
            } => {
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(&cumulative_supply.to_le_bytes());
                out.extend_from_slice(nullifier_pk);
                out.extend_from_slice(burn_proof_hash);
            }
            RecordBody::Seize {
                coin_id,
                amount,
                cumulative_supply,
                evidence_pack_hash,
            } => {
                out.extend_from_slice(&coin_id.to_bytes());
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(&cumulative_supply.to_le_bytes());
                out.extend_from_slice(evidence_pack_hash);
            }
            RecordBody::RotateKey { new_issuer_pk } => out.extend_from_slice(new_issuer_pk),
            RecordBody::Renounce => {}
            RecordBody::MetadataUpdate {
                new_extended_metadata_hash,
            } => out.extend_from_slice(new_extended_metadata_hash),
            RecordBody::FreezeUpdate {
                new_frozen_root,
                delta_hash,
            } => {
                out.extend_from_slice(&new_frozen_root.to_bytes());
                out.extend_from_slice(delta_hash);
            }
        }
        out
    }

    /// The hash that the next record's `prevRecordHash` links to.
    pub fn record_hash(&self) -> Digest {
        h_sponge(Domain::Record, &bytes_to_limbs16(&self.canonical_bytes()))
    }

    /// The 32-byte message an issuer signs (BIP340 over a tagged hash).
    pub fn signing_message(&self) -> [u8; 32] {
        tagged_hash(REC_TAG, &[&self.canonical_bytes()])
    }

    /// Strict decode of [`Self::canonical_bytes`].
    pub fn from_canonical_bytes(b: &[u8]) -> Option<Record> {
        if b.len() < 1 + 32 + 8 + 32 {
            return None;
        }
        let kind = RecordKind::from_u8(b[0])?;
        let asset_id = Digest::from_bytes(&b[1..33].try_into().unwrap())?;
        let seq = u64::from_le_bytes(b[33..41].try_into().unwrap());
        let prev_record_hash = Digest::from_bytes(&b[41..73].try_into().unwrap())?;
        let body_bytes = &b[73..];
        let body = match kind {
            RecordKind::Genesis => {
                let g = Genesis::from_canonical_bytes(body_bytes)?;
                if g.asset_id() != asset_id || seq != 0 || !prev_record_hash.is_zero() {
                    return None;
                }
                RecordBody::Genesis(g)
            }
            RecordKind::Mint => {
                if body_bytes.len() != 8 + 8 + 32 {
                    return None;
                }
                RecordBody::Mint {
                    amount: u64::from_le_bytes(body_bytes[..8].try_into().unwrap()),
                    cumulative_supply: u64::from_le_bytes(body_bytes[8..16].try_into().unwrap()),
                    nullifier_pk: body_bytes[16..48].try_into().unwrap(),
                }
            }
            RecordKind::Burn => {
                if body_bytes.len() != 8 + 8 + 32 + 32 {
                    return None;
                }
                RecordBody::Burn {
                    amount: u64::from_le_bytes(body_bytes[..8].try_into().unwrap()),
                    cumulative_supply: u64::from_le_bytes(body_bytes[8..16].try_into().unwrap()),
                    nullifier_pk: body_bytes[16..48].try_into().unwrap(),
                    burn_proof_hash: body_bytes[48..80].try_into().unwrap(),
                }
            }
            RecordKind::Seize => {
                if body_bytes.len() != 32 + 8 + 8 + 32 {
                    return None;
                }
                RecordBody::Seize {
                    coin_id: Digest::from_bytes(&body_bytes[..32].try_into().unwrap())?,
                    amount: u64::from_le_bytes(body_bytes[32..40].try_into().unwrap()),
                    cumulative_supply: u64::from_le_bytes(body_bytes[40..48].try_into().unwrap()),
                    evidence_pack_hash: body_bytes[48..80].try_into().unwrap(),
                }
            }
            RecordKind::RotateKey => {
                if body_bytes.len() != 32 {
                    return None;
                }
                RecordBody::RotateKey {
                    new_issuer_pk: body_bytes.try_into().unwrap(),
                }
            }
            RecordKind::Renounce => {
                if !body_bytes.is_empty() {
                    return None;
                }
                RecordBody::Renounce
            }
            RecordKind::MetadataUpdate => {
                if body_bytes.len() != 32 {
                    return None;
                }
                RecordBody::MetadataUpdate {
                    new_extended_metadata_hash: body_bytes.try_into().unwrap(),
                }
            }
            RecordKind::FreezeUpdate => {
                if body_bytes.len() != 32 + 32 {
                    return None;
                }
                RecordBody::FreezeUpdate {
                    new_frozen_root: Digest::from_bytes(&body_bytes[..32].try_into().unwrap())?,
                    delta_hash: body_bytes[32..].try_into().unwrap(),
                }
            }
        };
        Some(Record {
            asset_id,
            seq,
            prev_record_hash,
            body,
        })
    }
}

/// A record plus its issuer signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord {
    pub record: Record,
    pub sig: [u8; 64],
}

impl SignedRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.record.canonical_bytes();
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<SignedRecord> {
        if b.len() < 64 {
            return None;
        }
        let (rec, sig) = b.split_at(b.len() - 64);
        Some(SignedRecord {
            record: Record::from_canonical_bytes(rec)?,
            sig: sig.try_into().unwrap(),
        })
    }

    /// Verify the issuer signature against `issuer_pk` (the key current at
    /// this record's position in the chain — rotation is the caller's job).
    pub fn verify(&self, issuer_pk: &XOnlyBytes) -> bool {
        bip340_verify(issuer_pk, &self.record.signing_message(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scsv_core::types::Policy;

    fn genesis() -> Genesis {
        Genesis {
            version: 1,
            issuer_pk: [7u8; 32],
            mint_auth_key_hash: Digest::ZERO,
            policy: Policy {
                public_supply: true,
                freezable: true,
                max_supply: 0,
                decimals: 6,
            },
            ticker: "USDS".into(),
            name: "Test".into(),
            uri: "https://x.example".into(),
            extended_metadata_hash: [1u8; 32],
        }
    }

    #[test]
    fn all_kinds_roundtrip() {
        let g = genesis();
        let bodies = [
            RecordBody::Genesis(g.clone()),
            RecordBody::Mint {
                amount: 5,
                cumulative_supply: 5,
                nullifier_pk: [2; 32],
            },
            RecordBody::Burn {
                amount: 1,
                cumulative_supply: 4,
                nullifier_pk: [3; 32],
                burn_proof_hash: [4; 32],
            },
            RecordBody::Seize {
                coin_id: g.asset_id(),
                amount: 2,
                cumulative_supply: 2,
                evidence_pack_hash: [5; 32],
            },
            RecordBody::RotateKey {
                new_issuer_pk: [6; 32],
            },
            RecordBody::Renounce,
            RecordBody::MetadataUpdate {
                new_extended_metadata_hash: [8; 32],
            },
            RecordBody::FreezeUpdate {
                new_frozen_root: g.asset_id(),
                delta_hash: [9; 32],
            },
        ];
        for (i, body) in bodies.into_iter().enumerate() {
            let rec = if matches!(body, RecordBody::Genesis(_)) {
                Record::genesis(&g)
            } else {
                Record {
                    asset_id: g.asset_id(),
                    seq: i as u64,
                    prev_record_hash: g.asset_id(),
                    body,
                }
            };
            let bytes = rec.canonical_bytes();
            let back = Record::from_canonical_bytes(&bytes).expect("decode");
            assert_eq!(back, rec);
            assert_eq!(back.record_hash(), rec.record_hash());
        }
    }

    #[test]
    fn genesis_record_selfconsistency_enforced() {
        let g = genesis();
        let mut rec = Record::genesis(&g);
        rec.seq = 1; // genesis must be seq 0
        assert!(Record::from_canonical_bytes(&rec.canonical_bytes()).is_none());
        let mut rec = Record::genesis(&g);
        rec.asset_id = Digest::ZERO; // must equal H(genesis)
        assert!(Record::from_canonical_bytes(&rec.canonical_bytes()).is_none());
    }

    #[test]
    fn signature_binds_record() {
        use scsv_native_crypto::{bip340_sign, s2c_sign, NullifierKeypair};
        let kp = NullifierKeypair::from_seed(&[1u8; 32]).unwrap();
        let g = {
            let mut g = genesis();
            g.issuer_pk = kp.pk;
            g
        };
        let rec = Record::genesis(&g);
        let sig = bip340_sign(&kp, &rec.signing_message());
        let sr = SignedRecord {
            record: rec.clone(),
            sig,
        };
        assert!(sr.verify(&kp.pk));
        // Wire roundtrip preserves validity.
        let back = SignedRecord::from_bytes(&sr.to_bytes()).unwrap();
        assert!(back.verify(&kp.pk));
        // Wrong key rejected.
        let other = NullifierKeypair::from_seed(&[2u8; 32]).unwrap();
        assert!(!sr.verify(&other.pk));
        // Tampered record rejected.
        let mut bad = sr.clone();
        bad.record.seq = 5;
        assert!(!bad.verify(&kp.pk));
        // A *nullifier* signature over the same 32 bytes must NOT verify as a
        // record signature: domains are not cross-signable.
        let (nsig, _open) = s2c_sign(&kp, &[0u8; 32], &rec.signing_message());
        let cross = SignedRecord {
            record: rec,
            sig: nsig.sig,
        };
        assert!(!cross.verify(&kp.pk));
    }
}
