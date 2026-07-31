//! A real JSON-RPC client for a `signal-cli` daemon in HTTP mode
//! (`signal-cli -a <account> daemon --http 127.0.0.1:8080`).
//!
//! Sending: the bundle is base64-encoded into a `data:` attachment URI and
//! attached to a Signal message tagged with the SCVB marker, so a payment is an
//! ordinary Signal message. Receiving: `receive` is polled; SCVB attachments are
//! read back from signal-cli's attachment store and decoded to bundles.
//!
//! There is no mock daemon. Live send/receive needs an operator-registered
//! account (registration needs a real phone number and cannot run in CI). The
//! daemon is local, so requests go straight to 127.0.0.1 with no proxy or TLS.
//! The request-building and envelope-parsing are pure functions, unit-tested
//! here without a daemon.

use std::path::PathBuf;

use scsv_wallet::CoinBundle;
use serde_json::{json, Value};

/// The message text that tags a Signal message as carrying a coin bundle.
pub const SCVB_MARKER: &str = "SCVB/1";

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("http transport: {0}")]
    Http(String),
    #[error("signal-cli rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("malformed rpc response: {0}")]
    BadResponse(String),
    #[error("attachment io: {0}")]
    Io(String),
    #[error("attachment did not decode to a coin bundle")]
    BadBundle,
}

/// How to reach the signal-cli daemon and which account to act as.
#[derive(Clone, Debug)]
pub struct SignalConfig {
    /// The daemon's JSON-RPC endpoint, e.g. `http://127.0.0.1:8080/api/v1/rpc`.
    pub rpc_url: String,
    /// The operator's registered account (E.164), e.g. `+15551234567`.
    pub account: String,
    /// signal-cli's attachment store (where received attachments are written).
    /// Defaults to `~/.local/share/signal-cli/attachments`.
    pub attachments_dir: PathBuf,
}

impl SignalConfig {
    /// Build a config, defaulting the attachment store to signal-cli's location.
    pub fn new(rpc_url: impl Into<String>, account: impl Into<String>) -> Self {
        let attachments_dir = default_attachments_dir();
        SignalConfig {
            rpc_url: rpc_url.into(),
            account: account.into(),
            attachments_dir,
        }
    }
}

fn default_attachments_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".local/share/signal-cli/attachments")
}

/// A coin bundle received over Signal, with its sender.
#[derive(Clone, Debug)]
pub struct ReceivedBundle {
    pub from: String,
    pub bundle: CoinBundle,
}

/// A signal-cli JSON-RPC client.
pub struct SignalTransport {
    cfg: SignalConfig,
    agent: ureq::Agent,
}

impl SignalTransport {
    pub fn new(cfg: SignalConfig) -> Self {
        SignalTransport {
            cfg,
            agent: ureq::agent(),
        }
    }

    /// Send `bundle` to `recipient` (an E.164 number) as a Signal attachment.
    pub fn send_bundle(&self, recipient: &str, bundle: &CoinBundle) -> Result<(), TransportError> {
        let params = send_params(&self.cfg.account, recipient, bundle);
        self.rpc("send", params)?;
        Ok(())
    }

    /// Poll the daemon for new messages and return every SCVB bundle found.
    /// `timeout_secs` is how long signal-cli waits for traffic before returning.
    pub fn receive_bundles(
        &self,
        timeout_secs: u64,
    ) -> Result<Vec<ReceivedBundle>, TransportError> {
        let params = json!({ "account": self.cfg.account, "timeout": timeout_secs });
        let resp = self.rpc("receive", params)?;
        let envelopes = resp
            .as_array()
            .ok_or_else(|| TransportError::BadResponse("receive result is not an array".into()))?;
        let mut out = Vec::new();
        for env in envelopes {
            for (from, attach_id) in scvb_attachments(env) {
                let path = self.cfg.attachments_dir.join(&attach_id);
                let bytes = std::fs::read(&path).map_err(|e| TransportError::Io(e.to_string()))?;
                let bundle = CoinBundle::from_bytes(&bytes).ok_or(TransportError::BadBundle)?;
                out.push(ReceivedBundle { from, bundle });
            }
        }
        Ok(out)
    }

    /// One JSON-RPC 2.0 round-trip to the daemon.
    fn rpc(&self, method: &str, params: Value) -> Result<Value, TransportError> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let body =
            serde_json::to_string(&req).map_err(|e| TransportError::BadResponse(e.to_string()))?;
        let text = self
            .agent
            .post(&self.cfg.rpc_url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| TransportError::Http(e.to_string()))?
            .into_string()
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let resp: Value =
            serde_json::from_str(&text).map_err(|e| TransportError::BadResponse(e.to_string()))?;
        parse_rpc_result(&resp)
    }
}

/// Build the `send` params: an SCVB-marked message carrying the bundle as a
/// base64 `data:` attachment URI.
fn send_params(account: &str, recipient: &str, bundle: &CoinBundle) -> Value {
    let uri = format!(
        "data:application/octet-stream;filename=coin.scvb;base64,{}",
        base64_encode(&bundle.to_bytes())
    );
    json!({
        "account": account,
        "recipient": [recipient],
        "message": SCVB_MARKER,
        "attachments": [uri],
    })
}

/// Extract the JSON-RPC `result`, or map an `error` to [`TransportError::Rpc`].
fn parse_rpc_result(resp: &Value) -> Result<Value, TransportError> {
    if let Some(err) = resp.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        return Err(TransportError::Rpc { code, message });
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| TransportError::BadResponse("no result field".into()))
}

/// Pull `(sender, attachmentId)` pairs for every SCVB-marked attachment in one
/// received envelope.
fn scvb_attachments(env: &Value) -> Vec<(String, String)> {
    let envelope = match env.get("envelope") {
        Some(e) => e,
        None => return Vec::new(),
    };
    let from = envelope
        .get("sourceNumber")
        .or_else(|| envelope.get("source"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let data = match envelope.get("dataMessage") {
        Some(d) => d,
        None => return Vec::new(),
    };
    // Only accept attachments on a message carrying the SCVB marker.
    if data.get("message").and_then(Value::as_str) != Some(SCVB_MARKER) {
        return Vec::new();
    }
    let attachments = data.get("attachments").and_then(Value::as_array);
    attachments
        .into_iter()
        .flatten()
        .filter_map(|a| {
            a.get("id")
                .and_then(Value::as_str)
                .map(|id| (from.clone(), id.to_string()))
        })
        .collect()
}

/// Minimal base64 (standard alphabet, padded) — avoids a dependency for the one
/// place the crate needs it.
fn base64_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use scsv_wallet::{CoinBundle, WireHop};

    fn bundle() -> CoinBundle {
        CoinBundle {
            chain_id: [0xCD; 32],
            hops: vec![WireHop {
                tx_hash: [1; 32],
                asset_id: [2; 32],
                salt: 0,
                is_mint: true,
                inputs: vec![],
                outputs: vec![],
                nullifiers: vec![],
                mint_record_loc: None,
                balance_proof: vec![],
            }],
            target_tx_hash: [1; 32],
            target_out_index: 0,
        }
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn send_params_carry_marker_and_recipient() {
        let p = send_params("+15550001111", "+15552223333", &bundle());
        assert_eq!(p["account"], "+15550001111");
        assert_eq!(p["recipient"][0], "+15552223333");
        assert_eq!(p["message"], SCVB_MARKER);
        let uri = p["attachments"][0].as_str().unwrap();
        assert!(uri.starts_with("data:application/octet-stream;filename=coin.scvb;base64,"));
    }

    #[test]
    fn rpc_error_is_surfaced() {
        let resp = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}});
        match parse_rpc_result(&resp) {
            Err(TransportError::Rpc { code, message }) => {
                assert_eq!(code, -32602);
                assert_eq!(message, "bad params");
            }
            other => panic!("expected rpc error, got {other:?}"),
        }
    }

    #[test]
    fn only_scvb_marked_attachments_are_collected() {
        let good = json!({
            "envelope": {
                "sourceNumber": "+15551234567",
                "dataMessage": {
                    "message": SCVB_MARKER,
                    "attachments": [{"id": "abc.bin", "contentType": "application/octet-stream"}]
                }
            }
        });
        assert_eq!(
            scvb_attachments(&good),
            vec![("+15551234567".to_string(), "abc.bin".to_string())]
        );

        // A message without the marker is ignored, even with an attachment.
        let unmarked = json!({
            "envelope": {
                "sourceNumber": "+1",
                "dataMessage": {"message": "hi", "attachments": [{"id": "x.bin"}]}
            }
        });
        assert!(scvb_attachments(&unmarked).is_empty());

        // A typing/receipt envelope with no dataMessage is ignored.
        let receipt = json!({"envelope": {"sourceNumber": "+1", "receiptMessage": {}}});
        assert!(scvb_attachments(&receipt).is_empty());
    }
}
