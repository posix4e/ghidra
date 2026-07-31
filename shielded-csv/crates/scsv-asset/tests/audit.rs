//! Supply-audit scenarios: pure-fold unit cases (hand-built blocks) plus a real
//! end-to-end audit against a spawned regtest node.

use scsv_asset::evidence::{BurnProof, MemoryEvidence, NoEvidence};
use scsv_asset::view::Anomaly;
use scsv_asset::{audit_blocks, audit_supply, RecordChainView};
use scsv_chain::index::{ScannedBlock, ScannedTx};
use scsv_chain::records::{Record, RecordBody, SignedRecord};
use scsv_chain::wire::Payload;
use scsv_chain::PublicationChain;
use scsv_core::hash::Digest;
use scsv_core::types::{ChainLoc, Genesis, Policy};
use scsv_native_crypto::{bip340_sign, NullifierKeypair, NullifierSig};

// --- Test issuer that builds a correctly linked, signed record chain ---

struct Issuer {
    kp: NullifierKeypair,
    genesis: Genesis,
    last_hash: Digest,
    seq: u64,
    supply: u64,
}

fn nullifier_pk(seed: u8) -> [u8; 32] {
    NullifierKeypair::from_seed(&[seed; 32]).unwrap().pk
}

impl Issuer {
    fn new(seed: u8, public_supply: bool, max_supply: u64) -> Self {
        let kp = NullifierKeypair::from_seed(&[seed; 32]).unwrap();
        let genesis = Genesis {
            version: 1,
            issuer_pk: kp.pk,
            mint_auth_key_hash: Digest::ZERO,
            policy: Policy {
                public_supply,
                freezable: true,
                max_supply,
                decimals: 6,
            },
            ticker: "USDS".into(),
            name: "Test Dollar".into(),
            uri: "https://issuer.example/scsv".into(),
            extended_metadata_hash: [3u8; 32],
        };
        let last_hash = Record::genesis(&genesis).record_hash();
        Issuer {
            kp,
            genesis,
            last_hash,
            seq: 0,
            supply: 0,
        }
    }

    fn sign(&self, rec: Record) -> SignedRecord {
        let sig = bip340_sign(&self.kp, &rec.signing_message());
        SignedRecord { record: rec, sig }
    }

    fn genesis_record(&self) -> SignedRecord {
        self.sign(Record::genesis(&self.genesis))
    }

    fn next(&mut self, body: RecordBody) -> Record {
        self.seq += 1;
        let rec = Record {
            asset_id: self.genesis.asset_id(),
            seq: self.seq,
            prev_record_hash: self.last_hash,
            body,
        };
        self.last_hash = rec.record_hash();
        rec
    }

    fn mint(&mut self, amount: u64, null_pk: [u8; 32]) -> SignedRecord {
        self.supply += amount;
        let cumulative_supply = self.supply;
        let rec = self.next(RecordBody::Mint {
            amount,
            cumulative_supply,
            nullifier_pk: null_pk,
        });
        self.sign(rec)
    }

    fn burn(&mut self, amount: u64, null_pk: [u8; 32], burn_proof_hash: [u8; 32]) -> SignedRecord {
        self.supply -= amount;
        let cumulative_supply = self.supply;
        let rec = self.next(RecordBody::Burn {
            amount,
            cumulative_supply,
            nullifier_pk: null_pk,
            burn_proof_hash,
        });
        self.sign(rec)
    }
}

fn nsig(pk: [u8; 32]) -> NullifierSig {
    NullifierSig { pk, sig: [0u8; 64] }
}

/// Build a one-transaction block at `height` carrying the given payloads.
fn block(height: u64, payloads: Vec<Payload>) -> ScannedBlock {
    ScannedBlock {
        height,
        hash: [height as u8; 32],
        txs: vec![ScannedTx {
            loc: ChainLoc {
                height,
                tx_index: 0,
            },
            txid: [height as u8; 32],
            payloads,
        }],
    }
}

// --- Pure-fold scenarios ---

#[test]
fn audit_equals_mints() {
    let mut iss = Issuer::new(1, true, 0);
    let g = iss.genesis_record();
    let asset = iss.genesis.asset_id();
    let np = nullifier_pk(9);
    let m1 = iss.mint(1_000_000, np);
    let m2 = iss.mint(500_000, nullifier_pk(10));

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![Payload::Record(m1.to_bytes()), Payload::Nullifier(nsig(np))],
        ),
        block(
            3,
            vec![
                Payload::Record(m2.to_bytes()),
                Payload::Nullifier(nsig(nullifier_pk(10))),
            ],
        ),
    ];
    let reports = audit_blocks(&blocks, &NoEvidence);
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert_eq!(r.asset_id, asset);
    assert_eq!(r.audited_supply, 1_500_000);
    assert_eq!(r.claimed_supply, 1_500_000);
    assert!(r.fully_backed);
    assert!(r.anomalies.is_empty(), "{:?}", r.anomalies);
}

#[test]
fn mint_without_copublished_nullifier_rejected() {
    let mut iss = Issuer::new(2, true, 0);
    let g = iss.genesis_record();
    let m1 = iss.mint(100, nullifier_pk(1));
    // The mint record is present but its nullifier is NOT in the tx.
    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(2, vec![Payload::Record(m1.to_bytes())]),
    ];
    let r = &audit_blocks(&blocks, &NoEvidence)[0];
    assert_eq!(r.audited_supply, 0);
    assert!(matches!(
        r.anomalies[0],
        Anomaly::MissingCoPublishedNullifier { .. }
    ));
}

#[test]
fn bad_arithmetic_mint_rejected() {
    let mut iss = Issuer::new(3, true, 0);
    let g = iss.genesis_record();
    // Hand-craft a mint whose cumulative_supply lies.
    let np = nullifier_pk(1);
    iss.seq = 1;
    let bad = iss.sign(Record {
        asset_id: iss.genesis.asset_id(),
        seq: 1,
        prev_record_hash: Record::genesis(&iss.genesis).record_hash(),
        body: RecordBody::Mint {
            amount: 100,
            cumulative_supply: 999,
            nullifier_pk: np,
        },
    });
    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![
                Payload::Record(bad.to_bytes()),
                Payload::Nullifier(nsig(np)),
            ],
        ),
    ];
    let r = &audit_blocks(&blocks, &NoEvidence)[0];
    assert_eq!(r.audited_supply, 0);
    assert!(matches!(r.anomalies[0], Anomaly::BadArithmetic { .. }));
}

#[test]
fn equivocation_second_record_at_same_seq_ignored() {
    let mut iss = Issuer::new(4, true, 0);
    let g = iss.genesis_record();
    let np = nullifier_pk(1);
    let m1 = iss.mint(100, np);
    // A competing record at seq 1 (rewind the issuer and mint differently).
    let mut iss2 = Issuer::new(4, true, 0);
    let _ = iss2.genesis_record();
    let m1b = iss2.mint(777, nullifier_pk(2));

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![Payload::Record(m1.to_bytes()), Payload::Nullifier(nsig(np))],
        ),
        block(
            3,
            vec![
                Payload::Record(m1b.to_bytes()),
                Payload::Nullifier(nsig(nullifier_pk(2))),
            ],
        ),
    ];
    let r = &audit_blocks(&blocks, &NoEvidence)[0];
    assert_eq!(r.audited_supply, 100, "first record at seq 1 wins");
    assert!(r
        .anomalies
        .iter()
        .any(|a| matches!(a, Anomaly::Equivocation { .. })));
}

#[test]
fn provable_burn_counted_only_with_evidence() {
    let mut iss = Issuer::new(5, true, 0);
    let g = iss.genesis_record();
    let asset = iss.genesis.asset_id();
    let np = nullifier_pk(1);
    let m1 = iss.mint(1000, np);

    let proof = BurnProof {
        asset_id: asset,
        amount: 400,
        coin_id: Digest::ZERO,
    };
    let bp_hash = proof.hash();
    let bnp = nullifier_pk(2);
    let b1 = iss.burn(400, bnp, bp_hash);

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![Payload::Record(m1.to_bytes()), Payload::Nullifier(nsig(np))],
        ),
        block(
            3,
            vec![
                Payload::Record(b1.to_bytes()),
                Payload::Nullifier(nsig(bnp)),
            ],
        ),
    ];

    // Without evidence: burn not counted → conservative-high.
    let r = &audit_blocks(&blocks, &NoEvidence)[0];
    assert_eq!(r.audited_supply, 1000);
    assert_eq!(r.claimed_supply, 600);
    assert!(!r.fully_backed);
    assert!(r
        .anomalies
        .iter()
        .any(|a| matches!(a, Anomaly::MissingBurnEvidence { .. })));

    // With evidence: burn counted.
    let mut store = MemoryEvidence::new();
    store.put_burn(&proof);
    let r = &audit_blocks(&blocks, &store)[0];
    assert_eq!(r.audited_supply, 600);
    assert_eq!(r.claimed_supply, 600);
    assert!(r.fully_backed);
}

#[test]
fn key_rotation_changes_valid_signer() {
    let mut iss = Issuer::new(6, true, 0);
    let g = iss.genesis_record();
    let new_kp = NullifierKeypair::from_seed(&[99u8; 32]).unwrap();
    let rotate_rec = iss.next(RecordBody::RotateKey {
        new_issuer_pk: new_kp.pk,
    });
    let rotate = iss.sign(rotate_rec);

    // A mint signed by the OLD key after rotation must be rejected.
    let np = nullifier_pk(1);
    iss.supply += 100;
    let cumulative_supply = iss.supply;
    let mint_rec = iss.next(RecordBody::Mint {
        amount: 100,
        cumulative_supply,
        nullifier_pk: np,
    });
    let old_signed_mint = iss.sign(mint_rec);

    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(2, vec![Payload::Record(rotate.to_bytes())]),
        block(
            3,
            vec![
                Payload::Record(old_signed_mint.to_bytes()),
                Payload::Nullifier(nsig(np)),
            ],
        ),
    ];
    let r = &audit_blocks(&blocks, &NoEvidence)[0];
    assert_eq!(r.audited_supply, 0);
    assert!(r
        .anomalies
        .iter()
        .any(|a| matches!(a, Anomaly::BadSignature { .. })));
}

#[test]
fn max_supply_enforced() {
    let mut iss = Issuer::new(7, true, 1000);
    let g = iss.genesis_record();
    let np = nullifier_pk(1);
    let over = iss.mint(2000, np); // exceeds max 1000
    let blocks = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![
                Payload::Record(over.to_bytes()),
                Payload::Nullifier(nsig(np)),
            ],
        ),
    ];
    let r = &audit_blocks(&blocks, &NoEvidence)[0];
    assert_eq!(r.audited_supply, 0);
    assert!(r
        .anomalies
        .iter()
        .any(|a| matches!(a, Anomaly::MaxSupplyExceeded { .. })));
}

#[test]
fn reorg_rewind_via_refold() {
    // Folding a truncated block list yields the state as of that height.
    let mut iss = Issuer::new(8, true, 0);
    let g = iss.genesis_record();
    let np = nullifier_pk(1);
    let m1 = iss.mint(100, np);
    let m2 = iss.mint(200, nullifier_pk(2));
    let all = vec![
        block(1, vec![Payload::Record(g.to_bytes())]),
        block(
            2,
            vec![Payload::Record(m1.to_bytes()), Payload::Nullifier(nsig(np))],
        ),
        block(
            3,
            vec![
                Payload::Record(m2.to_bytes()),
                Payload::Nullifier(nsig(nullifier_pk(2))),
            ],
        ),
    ];
    let full = RecordChainView::build(&all, &NoEvidence);
    let rewound = RecordChainView::build(&all[..2], &NoEvidence);
    let asset = iss.genesis.asset_id();
    assert_eq!(full.asset(&asset).unwrap().audited_supply, 300);
    assert_eq!(rewound.asset(&asset).unwrap().audited_supply, 100);
}

// --- Real end-to-end audit against a spawned regtest node ---

#[test]
fn audit_over_real_regtest_chain() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let (start, _) = chain.tip().unwrap();

    let mut iss = Issuer::new(20, true, 0);
    let g = iss.genesis_record();
    chain.publish(&[Payload::Record(g.to_bytes())]).unwrap();
    chain.mine(1).unwrap();

    let np = nullifier_pk(30);
    let m1 = iss.mint(2_500_000, np);
    // Mint record and its nullifier co-published in one transaction (S3).
    chain
        .publish(&[Payload::Record(m1.to_bytes()), Payload::Nullifier(nsig(np))])
        .unwrap();
    chain.mine(1).unwrap();

    let reports = audit_supply(&chain, &NoEvidence, start + 1, None).unwrap();
    let r = reports
        .iter()
        .find(|r| r.asset_id == iss.genesis.asset_id())
        .expect("our asset in the audit");
    assert_eq!(r.audited_supply, 2_500_000);
    assert!(r.fully_backed);
    assert!(r.anomalies.is_empty(), "{:?}", r.anomalies);
}
