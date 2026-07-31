//! End-to-end scenarios for Shielded CSV, exercised against a real regtest node
//! with real full-parameter proofs. The flagship is the Tether scenario
//! (`spec/00-OVERVIEW.md`, `spec/10-PUBLIC-SUPPLY.md`): a public-supply,
//! freezable stablecoin whose mints, burns, freezes, and seizures are all
//! publicly auditable from a Bitcoin node alone, while transfers stay shielded.
//!
//! The scenario is a library function taking a `&BitcoindChain`, so both the
//! integration test (`tests/tether.rs`) and the CLI (`scsv demo tether`) drive
//! the same code: the test spawns the node and asserts, the CLI spawns the node
//! and prints the audited timeline.

use p3_field::PrimeCharacteristicRing;
use scsv_asset::view::SupplyEvent;
use scsv_asset::AssetReport;
use scsv_chain::BitcoindChain;
use scsv_core::hash::Digest;
use scsv_core::types::{Genesis, Policy};
use scsv_core::F;
use scsv_wallet::{RejectReason, Wallet, WalletError};

/// Confirmations required on every ancestry nullifier (S6). Kept small so the
/// scenario mines few blocks; proofs, not blocks, dominate the runtime.
const CONF: u64 = 1;

/// The outcome of the Tether scenario, with enough detail for the test to assert
/// reconciliation and for the CLI to print the audited timeline.
#[derive(Clone, Debug)]
pub struct TetherReport {
    pub asset_id: [u8; 32],
    pub ticker: String,
    /// Supply the audit stands behind (mints − proven burns/seizes).
    pub audited_supply: u64,
    /// Supply as the issuer's records claim it.
    pub claimed_supply: u64,
    /// True when every burn/seize was backed by valid evidence.
    pub fully_backed: bool,
    pub frozen_count: usize,
    pub seized_count: usize,
    /// The reason Dave's receive of the frozen coin was rejected.
    pub blocked_spend: RejectReason,
    /// Final shielded balances of the named holders.
    pub balances: Vec<(String, u64)>,
    /// Human-readable supply timeline from the final audit.
    pub timeline: Vec<String>,
    /// Step-by-step narrative of the scenario as it ran.
    pub narrative: Vec<String>,
}

impl TetherReport {
    /// Render the report the way the CLI prints it.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Tether scenario — asset {} ({})\n\n",
            hex::encode(&self.asset_id[..8]),
            self.ticker
        ));
        for line in &self.narrative {
            out.push_str(&format!("  {line}\n"));
        }
        out.push_str("\nAudited timeline (public, from the chain alone):\n");
        for ev in &self.timeline {
            out.push_str(&format!("  {ev}\n"));
        }
        out.push_str("\nFinal shielded balances (private, off-chain):\n");
        for (who, amt) in &self.balances {
            out.push_str(&format!("  {who:<10} {amt}\n"));
        }
        out.push_str(&format!(
            "\nAudit: audited_supply={} claimed_supply={} fully_backed={} frozen={} seized={}\n",
            self.audited_supply,
            self.claimed_supply,
            self.fully_backed,
            self.frozen_count,
            self.seized_count
        ));
        out
    }
}

#[derive(Debug)]
pub enum DemoError {
    Wallet(WalletError),
    /// A step expected to be rejected on receive actually succeeded.
    ExpectedRejection(&'static str),
    Other(String),
}

impl std::fmt::Display for DemoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemoError::Wallet(e) => write!(f, "wallet: {e}"),
            DemoError::ExpectedRejection(s) => write!(f, "expected rejection at {s}"),
            DemoError::Other(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for DemoError {}
impl From<WalletError> for DemoError {
    fn from(e: WalletError) -> Self {
        DemoError::Wallet(e)
    }
}

fn secret(seed: u32) -> Digest {
    Digest([F::from_u32(seed); 8])
}

fn describe(ev: &SupplyEvent) -> String {
    match ev {
        SupplyEvent::Genesis { loc } => format!("genesis           @ height {}", loc.height),
        SupplyEvent::Mint { amount, loc } => {
            format!("mint      {amount:>10} @ height {}", loc.height)
        }
        SupplyEvent::Burn {
            amount,
            counted,
            loc,
        } => format!(
            "burn      {amount:>10} @ height {} (counted={counted})",
            loc.height
        ),
        SupplyEvent::Seize {
            amount,
            counted,
            loc,
            ..
        } => format!(
            "seize     {amount:>10} @ height {} (counted={counted})",
            loc.height
        ),
        SupplyEvent::RotateKey { loc } => format!("rotate-key        @ height {}", loc.height),
        SupplyEvent::Renounce { loc } => format!("renounce          @ height {}", loc.height),
        SupplyEvent::MetadataUpdate { loc } => {
            format!("metadata-update   @ height {}", loc.height)
        }
        SupplyEvent::FreezeUpdate { loc, .. } => {
            format!("freeze-update     @ height {}", loc.height)
        }
    }
}

/// The USDT-style genesis: public supply (all mints/burns on-chain), freezable,
/// no cap.
fn tether_genesis() -> Genesis {
    Genesis {
        version: 1,
        issuer_pk: [0u8; 32], // create_asset fills in the derived issuer key
        mint_auth_key_hash: Digest::ZERO,
        policy: Policy {
            public_supply: true,
            freezable: true,
            max_supply: 0,
            decimals: 6,
        },
        ticker: "USDT".into(),
        name: "Demo Tether".into(),
        uri: "https://issuer.example/usdt".into(),
        extended_metadata_hash: [0x5c; 32],
    }
}

/// Run the full Tether lifecycle on `chain`:
/// public genesis → mints → audit == mints → shielded A→B→C → provable burn →
/// freeze → blocked spend → seize with evidence → replacement mint → final
/// audit reconciles.
pub fn run_tether_scenario(chain: &BitcoindChain) -> Result<TetherReport, DemoError> {
    let mut narrative = Vec::new();

    let mut issuer = Wallet::new(secret(9_000_001), chain.chain_id());
    let mut alice = Wallet::new(secret(9_000_002), chain.chain_id());
    let mut bob = Wallet::new(secret(9_000_003), chain.chain_id());
    let mut carol = Wallet::new(secret(9_000_004), chain.chain_id());
    let mut dave = Wallet::new(secret(9_000_005), chain.chain_id());
    let mut eve = Wallet::new(secret(9_000_006), chain.chain_id());

    // 1. Public genesis.
    let asset = issuer.create_asset(chain, tether_genesis(), CONF)?;
    let asset_bytes = asset.to_bytes();
    narrative.push(format!(
        "issuer published a public-supply genesis for USDT (asset {})",
        hex::encode(&asset_bytes[..8])
    ));

    // 2. Mints: 1,000,000 to Alice and 200,000 to the issuer's own treasury.
    let alice_addr = alice.new_address();
    let mint_a = issuer.mint(chain, 1_000_000, alice_addr, CONF)?;
    alice.receive(chain, &mint_a, CONF)?;
    let treasury_addr = issuer.new_address();
    issuer.mint(chain, 200_000, treasury_addr, CONF)?;
    // The issuer's own mint is auto-owned; find its index for the later burn.
    let treasury_idx = issuer
        .coins()
        .iter()
        .position(|c| !c.spent && c.coin.amount == 200_000)
        .ok_or_else(|| DemoError::Other("treasury coin not owned".into()))?;
    narrative.push("minted 1,000,000 to Alice and 200,000 to the issuer treasury".into());

    // 3. Audit == mints.
    let r = issuer.audit(chain)?;
    if r.audited_supply != 1_200_000 || !r.fully_backed {
        return Err(DemoError::Other(format!(
            "post-mint audit off: {} backed={}",
            r.audited_supply, r.fully_backed
        )));
    }
    narrative.push(format!(
        "audit after mints: supply {} (fully backed)",
        r.audited_supply
    ));

    // 4. Shielded A→B→C. Only nullifiers touch the chain; amounts stay private.
    let to_bob = alice.send(chain, 0, 600_000, bob.new_address(), CONF)?;
    bob.receive(chain, &to_bob, CONF)?;
    let to_carol = bob.send(chain, 0, 250_000, carol.new_address(), CONF)?;
    let carol_coin = carol.receive(chain, &to_carol, CONF)?;
    narrative.push(
        "shielded transfers: Alice→Bob 600,000, Bob→Carol 250,000 (only nullifiers on-chain)"
            .into(),
    );

    // 5. Provable burn of the treasury coin.
    let burned = issuer.burn(chain, treasury_idx, CONF)?;
    narrative.push(format!(
        "issuer provably burned {burned} from treasury (proof hosted off-chain)"
    ));
    let r = issuer.audit(chain)?;
    if r.audited_supply != 1_000_000 || !r.fully_backed {
        return Err(DemoError::Other(format!(
            "post-burn audit off: {} backed={}",
            r.audited_supply, r.fully_backed
        )));
    }
    narrative.push(format!(
        "audit after burn: supply {} (fully backed)",
        r.audited_supply
    ));

    // 6. Freeze Carol's coin, then a spend of it is blocked at receive.
    let carol_handle = carol_coin.coin_id();
    issuer.freeze(chain, &[carol_handle], CONF)?;
    narrative
        .push("issuer froze Carol's coin handle (FREEZE-UPDATE on-chain; delta off-chain)".into());

    let evidence = issuer.evidence().expect("issuer evidence").clone();
    let blocked_bundle = carol.send(chain, 0, 250_000, dave.new_address(), CONF)?;
    let blocked_spend = match dave.receive_with_evidence(chain, &blocked_bundle, CONF, &evidence) {
        Ok(_) => return Err(DemoError::ExpectedRejection("frozen spend Carol→Dave")),
        Err(WalletError::Rejected(reason)) => reason,
        Err(e) => return Err(DemoError::Wallet(e)),
    };
    narrative.push(format!(
        "Carol→Dave rejected on receive: {blocked_spend:?} (freeze enforced natively) — \
         Carol's attempt published the nullifier, so the frozen coin is now stranded: \
         consumed on-chain yet credited to no one"
    ));

    // 7. Seize the frozen coin with an evidence pack.
    issuer.seize(chain, carol_handle, 250_000, CONF)?;
    narrative.push("issuer seized the frozen coin (SEIZE record + evidence pack)".into());

    // 8. Replacement mint to Eve (auditable public supply restored).
    let mint_r = issuer.mint(chain, 250_000, eve.new_address(), CONF)?;
    eve.receive(chain, &mint_r, CONF)?;
    narrative.push("issuer minted 250,000 replacement to Eve".into());

    // 9. Final audit reconciles.
    let report: AssetReport = issuer.audit(chain)?;
    narrative.push(format!(
        "final audit: supply {} (fully backed={}, frozen={}, seized={})",
        report.audited_supply, report.fully_backed, report.frozen_count, report.seized_count
    ));

    let balances = vec![
        ("Alice".into(), alice.balance(&asset_bytes)),
        ("Bob".into(), bob.balance(&asset_bytes)),
        ("Carol".into(), carol.balance(&asset_bytes)),
        ("Dave".into(), dave.balance(&asset_bytes)),
        ("Eve".into(), eve.balance(&asset_bytes)),
    ];
    let timeline = report.timeline.iter().map(describe).collect();

    Ok(TetherReport {
        asset_id: asset_bytes,
        ticker: report.ticker.clone(),
        audited_supply: report.audited_supply,
        claimed_supply: report.claimed_supply,
        fully_backed: report.fully_backed,
        frozen_count: report.frozen_count,
        seized_count: report.seized_count,
        blocked_spend,
        balances,
        timeline,
        narrative,
    })
}
