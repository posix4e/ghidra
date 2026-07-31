//! OP_RETURN payload framing (`spec/07-CHAIN-EMBEDDING.md`).
//!
//! Every payload starts `SCSV | version | payloadKind`. Kind 1 carries a
//! nullifier (pk ‖ sig); kind 2 carries a signed issuer record
//! (`crate::records`). Parsing is strict: bad magic/version/length yields
//! `None` and the output is ignored by scanners.

use scsv_native_crypto::NullifierSig;

pub const MAGIC: &[u8; 4] = b"SCSV";
pub const VERSION: u8 = 1;

pub const KIND_NULLIFIER: u8 = 1;
pub const KIND_RECORD: u8 = 2;

/// A parsed on-chain payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    Nullifier(NullifierSig),
    /// A signed record, kept as raw bytes here; `crate::records` parses it.
    Record(Vec<u8>),
}

impl Payload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + 96);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        match self {
            Payload::Nullifier(n) => {
                out.push(KIND_NULLIFIER);
                out.extend_from_slice(&n.pk);
                out.extend_from_slice(&n.sig);
            }
            Payload::Record(bytes) => {
                out.push(KIND_RECORD);
                out.extend_from_slice(bytes);
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> Option<Payload> {
        if data.len() < 6 || &data[..4] != MAGIC || data[4] != VERSION {
            return None;
        }
        let body = &data[6..];
        match data[5] {
            KIND_NULLIFIER => {
                if body.len() != 96 {
                    return None;
                }
                Some(Payload::Nullifier(NullifierSig {
                    pk: body[..32].try_into().unwrap(),
                    sig: body[32..].try_into().unwrap(),
                }))
            }
            KIND_RECORD => {
                if body.is_empty() {
                    return None;
                }
                Some(Payload::Record(body.to_vec()))
            }
            _ => None,
        }
    }
}

/// Frame several payloads into one OP_RETURN datum: `count:u16 LE` then, per
/// payload, `len:u16 LE ‖ bytes`. Co-publishing in a single output keeps a
/// mint/burn record and its nullifier in the same Bitcoin transaction (S3) and
/// sidesteps Core's refusal to build multiple `data` outputs via
/// `createrawtransaction`.
pub fn encode_bundle(payloads: &[Payload]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(payloads.len() as u16).to_le_bytes());
    for p in payloads {
        let enc = p.encode();
        out.extend_from_slice(&(enc.len() as u16).to_le_bytes());
        out.extend_from_slice(&enc);
    }
    out
}

/// Strictly parse a payload bundle; returns `None` on any framing error so a
/// malformed OP_RETURN is ignored wholesale.
pub fn decode_bundle(data: &[u8]) -> Option<Vec<Payload>> {
    if data.len() < 2 {
        return None;
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut rest = &data[2..];
    let mut payloads = Vec::with_capacity(count);
    for _ in 0..count {
        if rest.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2..];
        if rest.len() < len {
            return None;
        }
        payloads.push(Payload::decode(&rest[..len])?);
        rest = &rest[len..];
    }
    if !rest.is_empty() {
        return None;
    }
    Some(payloads)
}

/// Build the OP_RETURN scriptPubKey for a payload: `6a` + minimal push.
pub fn op_return_script(data: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(data.len() + 4);
    s.push(0x6a);
    match data.len() {
        0..=75 => s.push(data.len() as u8),
        76..=255 => {
            s.push(0x4c); // OP_PUSHDATA1
            s.push(data.len() as u8);
        }
        _ => {
            s.push(0x4d); // OP_PUSHDATA2
            s.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
    }
    s.extend_from_slice(data);
    s
}

/// Extract the single pushed datum from an OP_RETURN scriptPubKey, if it has
/// the canonical `6a <push>` shape.
pub fn parse_op_return_script(script: &[u8]) -> Option<&[u8]> {
    if script.first() != Some(&0x6a) {
        return None;
    }
    let rest = &script[1..];
    let (len, off) = match *rest.first()? {
        n @ 1..=75 => (n as usize, 1),
        0x4c => (*rest.get(1)? as usize, 2),
        0x4d => (
            u16::from_le_bytes([*rest.get(1)?, *rest.get(2)?]) as usize,
            3,
        ),
        _ => return None,
    };
    let data = rest.get(off..off + len)?;
    // Strict: no trailing bytes after the push.
    if rest.len() != off + len {
        return None;
    }
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_roundtrip() {
        let n = NullifierSig {
            pk: [3u8; 32],
            sig: [7u8; 64],
        };
        let p = Payload::Nullifier(n);
        let enc = p.encode();
        assert_eq!(enc.len(), 6 + 96);
        assert_eq!(Payload::decode(&enc).unwrap(), p);
    }

    #[test]
    fn record_roundtrip() {
        let p = Payload::Record(vec![1, 2, 3, 4]);
        assert_eq!(Payload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Payload::decode(b"").is_none());
        assert!(Payload::decode(b"SCSW\x01\x01xxxx").is_none());
        assert!(Payload::decode(b"SCSV\x02\x01xxxx").is_none()); // bad version
        assert!(Payload::decode(b"SCSV\x01\x09xxxx").is_none()); // bad kind
                                                                 // Nullifier with wrong body length.
        let mut enc = Payload::Nullifier(NullifierSig {
            pk: [0; 32],
            sig: [0; 64],
        })
        .encode();
        enc.pop();
        assert!(Payload::decode(&enc).is_none());
    }

    #[test]
    fn bundle_roundtrip() {
        let n = Payload::Nullifier(NullifierSig {
            pk: [1u8; 32],
            sig: [2u8; 64],
        });
        let r = Payload::Record(vec![9, 8, 7]);
        let bundle = encode_bundle(&[n.clone(), r.clone()]);
        assert_eq!(decode_bundle(&bundle).unwrap(), vec![n.clone(), r]);
        // Single-payload and empty bundles.
        assert_eq!(
            decode_bundle(&encode_bundle(std::slice::from_ref(&n))).unwrap(),
            vec![n]
        );
        assert_eq!(
            decode_bundle(&encode_bundle(&[])).unwrap(),
            Vec::<Payload>::new()
        );
        // Truncation rejected.
        let mut bundle = encode_bundle(&[Payload::Record(vec![1, 2, 3])]);
        bundle.pop();
        assert!(decode_bundle(&bundle).is_none());
    }

    #[test]
    fn op_return_script_roundtrip() {
        for len in [1usize, 75, 76, 100, 255, 256, 500] {
            let data = vec![0xABu8; len];
            let script = op_return_script(&data);
            assert_eq!(parse_op_return_script(&script).unwrap(), &data[..]);
        }
        // Trailing garbage rejected.
        let mut script = op_return_script(&[1, 2, 3]);
        script.push(0);
        assert!(parse_op_return_script(&script).is_none());
    }
}
