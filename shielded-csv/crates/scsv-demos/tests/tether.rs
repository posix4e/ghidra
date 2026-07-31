//! The flagship Tether scenario on a real spawned regtest node with real
//! full-parameter proofs: public genesis → mints → audit == mints → shielded
//! A→B→C → provable burn → freeze → blocked spend → seize with evidence →
//! replacement mint → the audit reconciles from the chain alone.

use scsv_demos::run_tether_scenario;
use scsv_wallet::RejectReason;

#[test]
fn tether_scenario_reconciles() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();

    let report = run_tether_scenario(&chain).expect("tether scenario runs end to end");

    // The frozen coin's spend was blocked on receive.
    assert_eq!(report.blocked_spend, RejectReason::CoinFrozen);

    // Supply reconciles: 1,000,000 + 200,000 mints − 200,000 burn − 250,000
    // seize + 250,000 replacement = 1,000,000, every reduction evidence-backed.
    assert_eq!(report.audited_supply, 1_000_000);
    assert_eq!(report.claimed_supply, 1_000_000);
    assert!(report.fully_backed, "every burn/seize was evidence-backed");
    assert_eq!(report.frozen_count, 1, "the seized handle stays frozen");
    assert_eq!(report.seized_count, 1);

    // Shielded balances: Alice kept 400,000 change; Bob kept 350,000 change;
    // Carol's attempt to move her frozen coin stranded it (nullifier published,
    // Dave refused it), so she holds nothing; Dave never received; Eve got the
    // replacement 250,000. The legitimate holders sum to the audited supply.
    let bal = |who: &str| {
        report
            .balances
            .iter()
            .find(|(n, _)| n == who)
            .map(|(_, a)| *a)
            .unwrap()
    };
    assert_eq!(bal("Alice"), 400_000);
    assert_eq!(bal("Bob"), 350_000);
    assert_eq!(bal("Carol"), 0, "frozen coin stranded by the blocked spend");
    assert_eq!(bal("Dave"), 0);
    assert_eq!(bal("Eve"), 250_000);
    let total: u64 = report.balances.iter().map(|(_, a)| *a).sum();
    assert_eq!(
        total, report.audited_supply,
        "holders sum to audited supply"
    );

    // The audited timeline is public: genesis, two mints, a burn, a freeze, a
    // seize, and the replacement mint — seven supply events.
    assert_eq!(report.timeline.len(), 7, "{:#?}", report.timeline);

    // No anomalies surfaced (all records well-formed and evidence-backed).
    // Print the rendered report so `cargo test -- --nocapture` shows the demo.
    println!("{}", report.render());
}
