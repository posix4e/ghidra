//! `RegtestNode`: spawn a real `bitcoind -regtest` for a test, tear it down on
//! drop. There is no mock and no skip path — a missing `bitcoind` is a hard
//! panic pointing at `ci/install-bitcoind.sh`.
//!
//! Learned the hard way and encoded here: Bitcoin Core v31 rejects
//! network-specific options (like `rpcport`) in the global config section, so
//! they go under `[regtest]`; and it needs an explicit large `-datacarriersize`
//! to relay our >80-byte OP_RETURN payloads.

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use scsv_chain::rpc::{Auth, RpcClient};
use scsv_chain::BitcoindChain;
use serde_json::json;

/// The node's datacarrier size (must exceed our largest payload).
pub const DATACARRIER_SIZE: usize = 1000;

/// A running regtest node with a temporary datadir.
pub struct RegtestNode {
    child: Child,
    datadir: PathBuf,
    rpc_port: u16,
    url: String,
    wallet_name: String,
}

/// Monotonic-ish port picker seed so parallel tests don't collide.
static PORT_SALT: AtomicU32 = AtomicU32::new(0);

fn free_port() -> u16 {
    // Bind to :0 to get a free port from the OS, then release it. There is an
    // inherent race, but combined with the per-call salt it is reliable enough
    // for tests, and bitcoind will fail loudly (not silently) on a collision.
    let _ = PORT_SALT.fetch_add(1, Ordering::Relaxed);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
}

fn bitcoind_bin() -> String {
    std::env::var("SCSV_BITCOIND").unwrap_or_else(|_| "bitcoind".to_string())
}

impl RegtestNode {
    /// Start a node and a loaded funding wallet, mining 101 blocks so coinbase
    /// matures and the wallet is spendable. Retries on the inherent
    /// pick-a-free-port race (a port can be taken between selection and
    /// bitcoind binding it), so this is reliable under parallel `cargo test`.
    pub fn start() -> RegtestNode {
        let mut last_err = String::new();
        for attempt in 0..5 {
            match Self::try_start() {
                Ok(node) => return node,
                Err(e) => last_err = e,
            }
            std::thread::sleep(Duration::from_millis(150 * (attempt + 1)));
        }
        panic!(
            "could not start a regtest bitcoind after 5 attempts: {last_err}. \
             Install it with `bash ci/install-bitcoind.sh` and ensure ~/.local/bin \
             is on PATH, or set SCSV_BITCOIND to its path."
        );
    }

    fn try_start() -> Result<RegtestNode, String> {
        let datadir = std::env::temp_dir().join(format!(
            "scsv-regtest-{}-{}",
            std::process::id(),
            PORT_SALT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&datadir).map_err(|e| format!("create datadir: {e}"))?;
        let rpc_port = free_port();

        // `listen=0` disables P2P entirely: tests are single-node, and without
        // it every node would try to bind the one default regtest P2P port
        // (18444) and all but the first would exit with status 1. `bind`ing the
        // RPC to a unique port is enough.
        let conf = format!(
            "server=1\n\
             txindex=1\n\
             listen=0\n\
             fallbackfee=0.0002\n\
             datacarrier=1\n\
             datacarriersize={DATACARRIER_SIZE}\n\
             [regtest]\n\
             rpcport={rpc_port}\n"
        );
        std::fs::write(datadir.join("bitcoin.conf"), conf)
            .map_err(|e| format!("write conf: {e}"))?;

        let mut child = Command::new(bitcoind_bin())
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            // bitcoind logs to <datadir>/regtest/debug.log; keep test output clean.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn: {e}"))?;

        let url = format!("http://127.0.0.1:{rpc_port}");
        let cookie = datadir.join("regtest").join(".cookie");
        let node = RpcClient::new(url.clone(), Auth::CookieFile(cookie));

        // Wait for RPC, but bail early (for a retry) if bitcoind exited — the
        // usual cause is a lost port race.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if node.call("getblockchaininfo", json!([])).is_ok() {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                let _ = std::fs::remove_dir_all(&datadir);
                return Err(format!(
                    "bitcoind exited early ({status}) on port {rpc_port}"
                ));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&datadir);
                return Err(format!("RPC did not come up within 30s on port {rpc_port}"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        let wallet_name = "scsv".to_string();
        node.call("createwallet", json!([wallet_name]))
            .map_err(|e| format!("createwallet: {e}"))?;
        let n = RegtestNode {
            child,
            datadir,
            rpc_port,
            url,
            wallet_name,
        };
        n.chain()
            .ensure_funds()
            .map_err(|e| format!("fund wallet: {e}"))?;
        Ok(n)
    }

    /// A `BitcoindChain` bound to this node's funding wallet.
    pub fn chain(&self) -> BitcoindChain {
        let cookie = self.datadir.join("regtest").join(".cookie");
        BitcoindChain::connect(
            self.url.clone(),
            Auth::CookieFile(cookie),
            &self.wallet_name,
            DATACARRIER_SIZE,
        )
        .expect("connect to regtest node")
    }

    pub fn rpc_port(&self) -> u16 {
        self.rpc_port
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        // Best-effort graceful stop, then kill, then remove the datadir.
        let cookie = self.datadir.join("regtest").join(".cookie");
        let node = RpcClient::new(self.url.clone(), Auth::CookieFile(cookie));
        let _ = node.call("stop", json!([]));
        // Give it a moment to flush, then ensure it's gone.
        for _ in 0..25 {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

/// One shared regtest node per test binary, started lazily and guarded by a
/// mutex so node-using tests run serially against it. This bounds each test
/// binary to a single `bitcoind` — spawning four at once (the default test
/// parallelism) contends on ports and resources and is flaky. Tests that share
/// this node must capture their own starting height and filter results by their
/// own identifiers, which they already do.
pub fn shared_node() -> MutexGuard<'static, RegtestNode> {
    static SHARED: OnceLock<Mutex<RegtestNode>> = OnceLock::new();
    SHARED
        .get_or_init(|| Mutex::new(RegtestNode::start()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Convenience: write a file (used by tests staging off-chain blobs).
pub fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("scsv-{}-{name}", std::process::id()));
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(bytes).expect("write temp file");
    path
}
