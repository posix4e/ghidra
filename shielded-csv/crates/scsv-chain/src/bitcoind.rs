//! `BitcoindChain`: the real Bitcoin Core publication layer.
//!
//! Publishing builds one raw transaction with an OP_RETURN output per payload,
//! funds it from the node wallet, signs, and broadcasts. Scanning pulls blocks
//! by height with `getblock` verbosity 2 and extracts SCSV OP_RETURN outputs.
//! There is no mock and no fallback; every method fails loudly if the node is
//! unreachable.

use scsv_core::types::ChainLoc;

use crate::index::{ScannedBlock, ScannedTx};
use crate::rpc::{Auth, RpcClient, RpcError};
use crate::wire::{op_return_script, parse_op_return_script, Payload};
use crate::PublicationChain;
use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("rpc: {0}")]
    Rpc(#[from] RpcError),
    #[error("node: {0}")]
    Node(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("payload exceeds node datacarrier policy ({0} bytes)")]
    PayloadTooLarge(usize),
}

/// A handle to a real Bitcoin Core node plus a funding wallet.
pub struct BitcoindChain {
    node: RpcClient,
    wallet: RpcClient,
    /// The node's configured `-datacarriersize`; publishing checks against it.
    datacarrier_size: usize,
    chain_id: [u8; 32],
}

impl BitcoindChain {
    /// Connect to a node at `url`, using wallet `wallet_name` for funding.
    /// The wallet must exist and be loaded (the regtest harness creates it).
    pub fn connect(
        url: impl Into<String>,
        auth: Auth,
        wallet_name: &str,
        datacarrier_size: usize,
    ) -> Result<Self, ChainError> {
        let node = RpcClient::new(url, auth);
        let wallet = node.wallet(wallet_name);
        // Fail loudly right now if the node is unreachable.
        let info = node.call("getblockchaininfo", json!([]))?;
        let chain = info
            .get("chain")
            .and_then(Value::as_str)
            .ok_or_else(|| ChainError::Node("missing chain in getblockchaininfo".into()))?;
        // chain_id domain-separates signatures across networks.
        let mut chain_id = [0u8; 32];
        let cb = chain.as_bytes();
        chain_id[..cb.len().min(32)].copy_from_slice(&cb[..cb.len().min(32)]);
        Ok(Self {
            node,
            wallet,
            datacarrier_size,
            chain_id,
        })
    }

    pub fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    /// Mine `n` blocks to a fresh wallet address (regtest). Returns the hashes.
    pub fn mine(&self, n: u64) -> Result<Vec<[u8; 32]>, ChainError> {
        let addr = self.wallet.call("getnewaddress", json!([]))?;
        let hashes = self.node.call("generatetoaddress", json!([n, addr]))?;
        parse_hash_array(&hashes)
    }

    /// Ensure the funding wallet holds spendable coins (regtest bootstrap:
    /// mine 101 blocks so coinbase matures).
    pub fn ensure_funds(&self) -> Result<(), ChainError> {
        let bal = self.wallet.call("getbalance", json!([]))?;
        if bal.as_f64().unwrap_or(0.0) <= 0.0 {
            self.mine(101)?;
        }
        Ok(())
    }

    /// Invalidate a block by hash (regtest reorg testing).
    pub fn invalidate_block(&self, hash: &[u8; 32]) -> Result<(), ChainError> {
        self.node.call("invalidateblock", json!([hex_be(hash)]))?;
        Ok(())
    }

    /// Reconsider a previously invalidated block.
    pub fn reconsider_block(&self, hash: &[u8; 32]) -> Result<(), ChainError> {
        self.node.call("reconsiderblock", json!([hex_be(hash)]))?;
        Ok(())
    }

    fn block_hash_at(&self, height: u64) -> Result<[u8; 32], ChainError> {
        let h = self.node.call("getblockhash", json!([height]))?;
        parse_hash(&h)
    }
}

impl PublicationChain for BitcoindChain {
    type Error = ChainError;

    fn publish(&self, payloads: &[Payload]) -> Result<[u8; 32], ChainError> {
        if payloads.is_empty() {
            return Err(ChainError::Node("publish called with no payloads".into()));
        }
        // All co-published payloads go in ONE OP_RETURN datum (S3). Core's
        // createrawtransaction refuses multiple `data` outputs, and one output
        // keeps the record and its nullifier atomically in the same tx.
        let data = crate::wire::encode_bundle(payloads);
        if data.len() > self.datacarrier_size {
            return Err(ChainError::PayloadTooLarge(data.len()));
        }
        let raw = self.node.call(
            "createrawtransaction",
            json!([[], [{ "data": hex(&data[..]) }]]),
        )?;
        let raw = raw
            .as_str()
            .ok_or_else(|| ChainError::Decode("createraw".into()))?;
        let funded = self.wallet.call("fundrawtransaction", json!([raw]))?;
        let funded_hex = funded
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| ChainError::Decode("fundraw".into()))?;
        let signed = self
            .wallet
            .call("signrawtransactionwithwallet", json!([funded_hex]))?;
        let signed_hex = signed
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| ChainError::Decode("signraw".into()))?;
        if !signed
            .get("complete")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(ChainError::Node("signing incomplete".into()));
        }
        let txid = self
            .wallet
            .call("sendrawtransaction", json!([signed_hex]))?;
        parse_hash(&txid)
    }

    fn tip(&self) -> Result<(u64, [u8; 32]), ChainError> {
        let height = self
            .node
            .call("getblockcount", json!([]))?
            .as_u64()
            .ok_or_else(|| ChainError::Decode("getblockcount".into()))?;
        let hash = self.block_hash_at(height)?;
        Ok((height, hash))
    }

    fn scan(&self, from_height: u64, to_height: u64) -> Result<Vec<ScannedBlock>, ChainError> {
        let mut blocks = Vec::new();
        for height in from_height..=to_height {
            let hash = self.block_hash_at(height)?;
            let block = self.node.call("getblock", json!([hex_be(&hash), 2]))?;
            blocks.push(parse_block(height, &hash, &block)?);
        }
        Ok(blocks)
    }

    fn locate(&self, txid: &[u8; 32]) -> Result<Option<ChainLoc>, ChainError> {
        // getrawtransaction verbose: needs txindex, which the harness enables.
        let tx = match self
            .node
            .call("getrawtransaction", json!([hex_be(txid), true]))
        {
            Ok(v) => v,
            Err(RpcError::Rpc { .. }) => return Ok(None), // unknown txid
            Err(e) => return Err(e.into()),
        };
        let Some(block_hash) = tx.get("blockhash").and_then(Value::as_str) else {
            return Ok(None); // unconfirmed
        };
        let header = self.node.call("getblockheader", json!([block_hash]))?;
        let height = header
            .get("height")
            .and_then(Value::as_u64)
            .ok_or_else(|| ChainError::Decode("blockheader height".into()))?;
        // Find the tx index within the block.
        let block = self.node.call("getblock", json!([block_hash, 1]))?;
        let want = hex_be(txid);
        let tx_index = block
            .get("tx")
            .and_then(Value::as_array)
            .and_then(|txs| txs.iter().position(|t| t.as_str() == Some(&want)))
            .ok_or_else(|| ChainError::Decode("tx not in its block".into()))?;
        Ok(Some(ChainLoc {
            height,
            tx_index: tx_index as u32,
        }))
    }
}

fn parse_block(height: u64, hash: &[u8; 32], block: &Value) -> Result<ScannedBlock, ChainError> {
    let txs_json = block
        .get("tx")
        .and_then(Value::as_array)
        .ok_or_else(|| ChainError::Decode("block.tx".into()))?;
    let mut txs = Vec::new();
    for (tx_index, tx) in txs_json.iter().enumerate() {
        let txid = parse_hash(tx.get("txid").unwrap_or(&Value::Null))?;
        let mut payloads = Vec::new();
        if let Some(vout) = tx.get("vout").and_then(Value::as_array) {
            for out in vout {
                let Some(hexs) = out
                    .get("scriptPubKey")
                    .and_then(|s| s.get("hex"))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                let Ok(script) = hex_decode(hexs) else {
                    continue;
                };
                if let Some(data) = parse_op_return_script(&script) {
                    if let Some(mut ps) = crate::wire::decode_bundle(data) {
                        payloads.append(&mut ps);
                    }
                }
            }
        }
        if !payloads.is_empty() {
            txs.push(ScannedTx {
                loc: ChainLoc {
                    height,
                    tx_index: tx_index as u32,
                },
                txid,
                payloads,
            });
        }
    }
    Ok(ScannedBlock {
        height,
        hash: *hash,
        txs,
    })
}

/// Bitcoin displays hashes as big-endian hex of the internal little-endian
/// bytes. We store the internal bytes; RPC wants the display form.
fn hex_be(h: &[u8; 32]) -> String {
    let mut rev = *h;
    rev.reverse();
    hex(&rev)
}

fn parse_hash(v: &Value) -> Result<[u8; 32], ChainError> {
    let s = v
        .as_str()
        .ok_or_else(|| ChainError::Decode("expected hash string".into()))?;
    let bytes = hex_decode(s).map_err(|e| ChainError::Decode(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(ChainError::Decode("hash not 32 bytes".into()));
    }
    let mut out: [u8; 32] = bytes.try_into().unwrap();
    out.reverse(); // display (BE) -> internal (LE)
    Ok(out)
}

fn parse_hash_array(v: &Value) -> Result<Vec<[u8; 32]>, ChainError> {
    v.as_array()
        .ok_or_else(|| ChainError::Decode("expected array".into()))?
        .iter()
        .map(parse_hash)
        .collect()
}

fn hex(b: &[u8]) -> String {
    hex_crate::encode(b)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, hex_crate::FromHexError> {
    hex_crate::decode(s)
}

// Re-export under a clear name to avoid clashing with the local `hex` fn.
use hex as hex_crate;

/// Build the OP_RETURN script for external callers/tests.
pub fn op_return_for(payload: &Payload) -> Vec<u8> {
    op_return_script(&payload.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_display_roundtrip() {
        let internal = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let disp = hex_be(&internal);
        let back = parse_hash(&Value::String(disp)).unwrap();
        assert_eq!(back, internal);
    }
}
