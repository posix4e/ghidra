//! Minimal Bitcoin Core JSON-RPC client over HTTP (ureq). Cookie or
//! user:password auth. No connection pooling, no async — the chain layer is
//! deliberately boring.

use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("http status {0}: {1}")]
    Http(u16, String),
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("malformed response: {0}")]
    Malformed(String),
    #[error("auth: {0}")]
    Auth(String),
}

/// How to authenticate against the node.
#[derive(Clone, Debug)]
pub enum Auth {
    /// Read `<datadir>/regtest/.cookie` fresh on every request (it changes on
    /// node restart).
    CookieFile(PathBuf),
    UserPass(String, String),
}

impl Auth {
    fn header(&self) -> Result<String, RpcError> {
        let creds = match self {
            Auth::CookieFile(p) => std::fs::read_to_string(p)
                .map_err(|e| RpcError::Auth(format!("read cookie {}: {e}", p.display())))?,
            Auth::UserPass(u, p) => format!("{u}:{p}"),
        };
        Ok(format!("Basic {}", base64(creds.trim().as_bytes())))
    }
}

/// Tiny standalone base64 (standard alphabet, padded) — not worth a dependency.
fn base64(input: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TBL[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TBL[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A JSON-RPC endpoint (`http://host:port`, optionally with `/wallet/<name>`).
#[derive(Clone, Debug)]
pub struct RpcClient {
    url: String,
    auth: Auth,
    agent: ureq::Agent,
}

impl RpcClient {
    pub fn new(url: impl Into<String>, auth: Auth) -> Self {
        // ureq does not pick up proxy env vars unless asked to; the node is
        // local, so a direct agent is exactly right.
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(30))
            .build();
        Self {
            url: url.into(),
            auth,
            agent,
        }
    }

    /// A client scoped to a wallet endpoint.
    pub fn wallet(&self, name: &str) -> RpcClient {
        RpcClient {
            url: format!("{}/wallet/{name}", self.url.trim_end_matches('/')),
            auth: self.auth.clone(),
            agent: self.agent.clone(),
        }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({"jsonrpc": "2.0", "id": "scsv", "method": method, "params": params});
        let resp = self
            .agent
            .post(&self.url)
            .set("Authorization", &self.auth.header()?)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());
        let text = match resp {
            Ok(r) => r
                .into_string()
                .map_err(|e| RpcError::Transport(e.to_string()))?,
            // Core returns RPC errors with non-200 statuses; the body still
            // carries the JSON-RPC error object.
            Err(ureq::Error::Status(code, r)) => {
                let t = r.into_string().unwrap_or_default();
                if t.is_empty() {
                    return Err(RpcError::Http(code, "empty body".into()));
                }
                t
            }
            Err(e) => return Err(RpcError::Transport(e.to_string())),
        };
        let v: Value = serde_json::from_str(&text).map_err(|e| {
            RpcError::Malformed(format!(
                "{e}: {}",
                &text.chars().take(200).collect::<String>()
            ))
        })?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("<none>")
                    .to_string(),
            });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RpcError::Malformed("missing result".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
