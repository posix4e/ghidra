//! `scsv` — command-line driver for Shielded CSV.
//!
//! Subcommands:
//! * `demo tether` — spawn a throwaway regtest node and run the full Tether
//!   lifecycle (public genesis → mints → shielded transfers → provable burn →
//!   freeze → blocked spend → seize → replacement mint → reconciling audit),
//!   printing the audited timeline.
//! * `audit` — connect to a running Bitcoin Core node and audit every Shielded
//!   CSV asset from the chain alone.
//! * `node-info` — print a node's chain and tip.
//!
//! `demo` needs `bitcoind` on PATH (see `ci/install-bitcoind.sh`); `audit` and
//! `node-info` talk to a node you already run.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use scsv_asset::evidence::NoEvidence;
use scsv_asset::{audit_supply, AssetReport};
use scsv_chain::rpc::Auth;
use scsv_chain::{BitcoindChain, PublicationChain};
use scsv_transport::{import_bundle, SignalConfig, SignalTransport};

/// Node-carrier size the regtest harness pins; also the default assumed for a
/// user-run node in `audit`/`node-info` (only the publish path enforces it).
const DATACARRIER_SIZE: usize = 1000;

#[derive(Parser)]
#[command(name = "scsv", version, about = "Shielded CSV for Bitcoin")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run an end-to-end demo on a spawned regtest node.
    Demo {
        #[command(subcommand)]
        which: DemoKind,
    },
    /// Audit every asset on a running node from the chain alone.
    Audit {
        /// Node JSON-RPC URL, e.g. http://127.0.0.1:18443
        #[arg(long)]
        rpc: String,
        /// Path to the node's `.cookie` file.
        #[arg(long)]
        cookie: PathBuf,
        /// Funding wallet name (unused by audit, but the client expects one).
        #[arg(long, default_value = "")]
        wallet: String,
        /// First height to scan (default 1).
        #[arg(long, default_value_t = 1)]
        from: u64,
    },
    /// Print a node's chain and current tip.
    NodeInfo {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        cookie: PathBuf,
        #[arg(long, default_value = "")]
        wallet: String,
    },
    /// Move coin bundles over Signal (via a running signal-cli daemon).
    Signal {
        #[command(subcommand)]
        which: SignalCmd,
    },
}

#[derive(Subcommand)]
enum SignalCmd {
    /// Send a bundle file to a recipient.
    Send {
        /// Recipient E.164 number, e.g. +15551234567.
        #[arg(long)]
        to: String,
        /// Path to the `.scvb` bundle to send.
        #[arg(long)]
        bundle: PathBuf,
        /// signal-cli daemon JSON-RPC URL (or env SCSV_SIGNAL_RPC).
        #[arg(long, env = "SCSV_SIGNAL_RPC")]
        rpc: String,
        /// This wallet's registered Signal account (or env SCSV_SIGNAL_ACCOUNT).
        #[arg(long, env = "SCSV_SIGNAL_ACCOUNT")]
        account: String,
    },
    /// Poll for incoming bundles and write each to `<out-dir>/<from>-<n>.scvb`.
    Listen {
        /// Directory to write received bundles into.
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// Seconds to wait for traffic per poll.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        #[arg(long, env = "SCSV_SIGNAL_RPC")]
        rpc: String,
        #[arg(long, env = "SCSV_SIGNAL_ACCOUNT")]
        account: String,
    },
}

#[derive(Subcommand)]
enum DemoKind {
    /// The flagship public-supply stablecoin lifecycle.
    Tether,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Demo {
            which: DemoKind::Tether,
        } => demo_tether(),
        Command::Audit {
            rpc,
            cookie,
            wallet,
            from,
        } => {
            let chain =
                BitcoindChain::connect(rpc, Auth::CookieFile(cookie), &wallet, DATACARRIER_SIZE)?;
            let reports = audit_supply(&chain, &NoEvidence, from, None)?;
            print_audit(&reports);
            Ok(())
        }
        Command::NodeInfo {
            rpc,
            cookie,
            wallet,
        } => {
            let chain =
                BitcoindChain::connect(rpc, Auth::CookieFile(cookie), &wallet, DATACARRIER_SIZE)?;
            let (height, hash) = chain.tip()?;
            println!("tip height {height}, hash {}", hex::encode(hash));
            Ok(())
        }
        Command::Signal { which } => signal(which),
    }
}

fn signal(cmd: SignalCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        SignalCmd::Send {
            to,
            bundle,
            rpc,
            account,
        } => {
            let b = import_bundle(&bundle)?;
            let transport = SignalTransport::new(SignalConfig::new(rpc, account));
            transport.send_bundle(&to, &b)?;
            println!("sent {} to {to}", bundle.display());
            Ok(())
        }
        SignalCmd::Listen {
            out_dir,
            timeout,
            rpc,
            account,
        } => {
            let transport = SignalTransport::new(SignalConfig::new(rpc, account));
            std::fs::create_dir_all(&out_dir)?;
            eprintln!("listening for bundles (Ctrl-C to stop)…");
            let mut n = 0u64;
            loop {
                let received = transport.receive_bundles(timeout)?;
                for rb in received {
                    let path = out_dir.join(format!("{}-{n}.scvb", sanitize(&rb.from)));
                    std::fs::write(&path, rb.bundle.to_bytes())?;
                    println!("received bundle from {} -> {}", rb.from, path.display());
                    n += 1;
                }
            }
        }
    }
}

/// Make a sender identifier safe for a filename.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn demo_tether() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("spawning a regtest bitcoind (needs bitcoind on PATH)…");
    let node = scsv_testkit::RegtestNode::start();
    let chain = node.chain();
    let report = scsv_demos::run_tether_scenario(&chain)?;
    print!("{}", report.render());
    Ok(())
}

fn print_audit(reports: &[AssetReport]) {
    if reports.is_empty() {
        println!("no Shielded CSV assets found in the scanned range");
        return;
    }
    println!("(auditing from the chain alone — burns/seizes without served evidence read conservative-high)");
    for r in reports {
        println!(
            "{} ({})  audited={} claimed={} backed={} frozen={} seized={} renounced={}",
            r.ticker,
            hex::encode(&r.asset_id.to_bytes()[..8]),
            r.audited_supply,
            r.claimed_supply,
            r.fully_backed,
            r.frozen_count,
            r.seized_count,
            r.renounced,
        );
        if !r.anomalies.is_empty() {
            println!("  anomalies: {:?}", r.anomalies);
        }
    }
}
