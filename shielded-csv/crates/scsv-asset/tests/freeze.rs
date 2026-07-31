//! Freeze and seizure scenarios (`spec/12-FREEZE.md`, `spec/13-SEIZURE.md`),
//! including a real end-to-end freeze+seize audit on a spawned regtest node.

mod common;
use common::*;

use p3_field::PrimeCharacteristicRing;
use scsv_asset::evidence::{MemoryEvidence, NoEvidence};
use scsv_asset::view::Anomaly;
use scsv_asset::{audit_blocks, audit_supply, RecordChainView};
use scsv_chain::wire::Payload;
use scsv_chain::PublicationChain;
use scsv_core::hash::Digest;
use scsv_core::F;

fn handle(n: u32) -> Digest {
    Digest(core::array::from_fn(|i| {
        F::from_u32(n * 1000 + i as u32 + 1)
    }))
}

#[test]
fn freeze_marks_handle_and_updates_root() {
    let mut ev = MemoryEvidence::new();
    let mut iss = Issuer::new(1, true, 0);
    let g = iss.genesis_record();
    let h = handle(1);
    let fu = iss.freeze_update(&[h], &[], &mut ev);

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(5, vec![Payload::Record(fu.to_bytes())]),
    ];
    let view = RecordChainView::build(&blocks, &ev);
    let a = view.asset(&iss.asset_id()).unwrap();
    assert!(a.is_frozen(&h));
    assert!(!a.is_frozen(&handle(2)));
    // frozen_root_at reflects the update from its height onward.
    assert_ne!(a.frozen_root_at(5), a.frozen_root_at(4));
    assert_eq!(a.frozen_root_at(4), a.frozen_root_at(1)); // empty before the freeze
}

#[test]
fn seize_requires_frozen_handle() {
    let mut ev = MemoryEvidence::new();
    let mut iss = Issuer::new(2, true, 0);
    let g = iss.genesis_record();
    let np = nullifier_pk(1);
    let m = iss.mint(1000, np);
    // Seize a handle that was never frozen.
    let s = iss.seize(handle(9), 400, &mut ev);

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![Payload::Record(m.to_bytes()), Payload::Nullifier(nsig(np))],
        ),
        block(3, vec![Payload::Record(s.to_bytes())]),
    ];
    let r = &audit_blocks(&blocks, &ev)[0];
    assert_eq!(
        r.audited_supply, 1000,
        "seize-without-freeze does not reduce supply"
    );
    assert!(r
        .anomalies
        .iter()
        .any(|a| matches!(a, Anomaly::SeizeWithoutFreeze { .. })));
}

#[test]
fn seize_of_frozen_handle_with_evidence_reduces_supply() {
    let mut ev = MemoryEvidence::new();
    let mut iss = Issuer::new(3, true, 0);
    let g = iss.genesis_record();
    let np = nullifier_pk(1);
    let m = iss.mint(1000, np);
    let h = handle(7);
    let fu = iss.freeze_update(&[h], &[], &mut ev);
    let s = iss.seize(h, 400, &mut ev);

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![Payload::Record(m.to_bytes()), Payload::Nullifier(nsig(np))],
        ),
        block(3, vec![Payload::Record(fu.to_bytes())]),
        block(4, vec![Payload::Record(s.to_bytes())]),
    ];
    let r = &audit_blocks(&blocks, &ev)[0];
    assert_eq!(r.audited_supply, 600);
    assert_eq!(r.claimed_supply, 600);
    assert!(r.fully_backed);
    assert_eq!(r.seized_count, 1);
}

#[test]
fn seize_without_evidence_is_conservative_high() {
    let mut ev = MemoryEvidence::new();
    let mut iss = Issuer::new(4, true, 0);
    let g = iss.genesis_record();
    let np = nullifier_pk(1);
    let m = iss.mint(1000, np);
    let h = handle(7);
    let fu = iss.freeze_update(&[h], &[], &mut ev);
    let s = iss.seize_no_evidence(h, 400);

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![Payload::Record(m.to_bytes()), Payload::Nullifier(nsig(np))],
        ),
        block(3, vec![Payload::Record(fu.to_bytes())]),
        block(4, vec![Payload::Record(s.to_bytes())]),
    ];
    // The delta is in `ev` but the seize evidence is not.
    let r = &audit_blocks(&blocks, &ev)[0];
    assert_eq!(r.audited_supply, 1000, "no evidence ⇒ conservative-high");
    assert_eq!(r.claimed_supply, 600);
    assert!(!r.fully_backed);
    assert!(r
        .anomalies
        .iter()
        .any(|a| matches!(a, Anomaly::MissingSeizeEvidence { .. })));
}

#[test]
fn unfreeze_of_seized_handle_is_rejected() {
    let mut ev = MemoryEvidence::new();
    let mut iss = Issuer::new(5, true, 0);
    let g = iss.genesis_record();
    let np = nullifier_pk(1);
    let m = iss.mint(1000, np);
    let h = handle(7);
    let fu = iss.freeze_update(&[h], &[], &mut ev);
    let s = iss.seize(h, 400, &mut ev);
    // Now try to unfreeze the seized handle — must be rejected (monotone).
    let unfreeze = iss.freeze_update(&[], &[h], &mut ev);

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![Payload::Record(m.to_bytes()), Payload::Nullifier(nsig(np))],
        ),
        block(3, vec![Payload::Record(fu.to_bytes())]),
        block(4, vec![Payload::Record(s.to_bytes())]),
        block(5, vec![Payload::Record(unfreeze.to_bytes())]),
    ];
    let view = RecordChainView::build(&blocks, &ev);
    let a = view.asset(&iss.asset_id()).unwrap();
    assert!(a.is_frozen(&h), "seized handle stays frozen");
    assert!(a
        .anomalies
        .iter()
        .any(|x| matches!(x, Anomaly::UnfreezeOfSeized { .. })));
}

#[test]
fn freeze_update_with_missing_delta_flagged() {
    let mut iss = Issuer::new(6, true, 0);
    let g = iss.genesis_record();
    let fu = iss.freeze_update_missing_delta(&[handle(1)]);
    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(2, vec![Payload::Record(fu.to_bytes())]),
    ];
    // NoEvidence resolves nothing, so the delta is unavailable.
    let view = RecordChainView::build(&blocks, &NoEvidence);
    let a = view.asset(&iss.asset_id()).unwrap();
    assert!(!a.is_frozen(&handle(1)));
    assert!(a
        .anomalies
        .iter()
        .any(|x| matches!(x, Anomaly::MissingFreezeDelta { .. })));
}

#[test]
fn freeze_update_with_wrong_root_flagged() {
    let mut ev = MemoryEvidence::new();
    let mut iss = Issuer::new(7, true, 0);
    let g = iss.genesis_record();
    let fu = iss.freeze_update_bad_root(&[handle(1)], &mut ev);
    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(2, vec![Payload::Record(fu.to_bytes())]),
    ];
    let view = RecordChainView::build(&blocks, &ev);
    let a = view.asset(&iss.asset_id()).unwrap();
    assert!(!a.is_frozen(&handle(1)));
    assert!(a
        .anomalies
        .iter()
        .any(|x| matches!(x, Anomaly::FreezeRootMismatch { .. })));
}

#[test]
fn frozen_root_at_grace_window() {
    let mut ev = MemoryEvidence::new();
    let mut iss = Issuer::new(8, true, 0);
    let g = iss.genesis_record();
    let f1 = iss.freeze_update(&[handle(1)], &[], &mut ev);
    let f2 = iss.freeze_update(&[handle(2)], &[], &mut ev);
    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(10, vec![Payload::Record(f1.to_bytes())]),
        block(20, vec![Payload::Record(f2.to_bytes())]),
    ];
    let view = RecordChainView::build(&blocks, &ev);
    let a = view.asset(&iss.asset_id()).unwrap();
    // Roots are stable within their validity windows.
    assert_eq!(a.frozen_root_at(10), a.frozen_root_at(19));
    assert_ne!(a.frozen_root_at(19), a.frozen_root_at(20));
    assert_eq!(a.frozen_root_at(20), a.frozen_root_at(100)); // latest sticks
}

#[test]
fn real_regtest_freeze_and_seize() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let (start, _) = chain.tip().unwrap();
    let mut ev = MemoryEvidence::new();

    let mut iss = Issuer::new(40, true, 0);
    let g = iss.genesis_record();
    chain.publish(&[Payload::Record(g.to_bytes())]).unwrap();
    chain.mine(1).unwrap();

    let np = nullifier_pk(41);
    let m = iss.mint(1_000_000, np);
    chain
        .publish(&[Payload::Record(m.to_bytes()), Payload::Nullifier(nsig(np))])
        .unwrap();
    chain.mine(1).unwrap();

    let h = handle(55);
    let fu = iss.freeze_update(&[h], &[], &mut ev);
    chain.publish(&[Payload::Record(fu.to_bytes())]).unwrap();
    chain.mine(1).unwrap();

    let s = iss.seize(h, 250_000, &mut ev);
    chain.publish(&[Payload::Record(s.to_bytes())]).unwrap();
    chain.mine(1).unwrap();

    let reports = audit_supply(&chain, &ev, start + 1, None).unwrap();
    let r = reports
        .iter()
        .find(|r| r.asset_id == iss.asset_id())
        .expect("asset");
    assert_eq!(r.audited_supply, 750_000, "mint 1,000,000 − seize 250,000");
    assert_eq!(r.seized_count, 1);
    assert!(r.fully_backed);
    assert!(r.anomalies.is_empty(), "{:?}", r.anomalies);
}
