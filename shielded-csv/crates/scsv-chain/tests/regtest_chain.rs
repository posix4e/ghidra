//! Integration tests for `BitcoindChain` against a REAL spawned regtest node.
//! No mocks: every assertion goes through Bitcoin Core RPC. A missing
//! `bitcoind` panics with an install hint (see the harness).

use scsv_chain::wire::Payload;
use scsv_chain::{NullifierIndex, PublicationChain, Record, SignedRecord};
use scsv_core::hash::Digest;
use scsv_core::types::{Genesis, Policy};
use scsv_native_crypto::{bip340_sign, s2c_sign, NullifierKeypair, NullifierSig};

fn nsig(seed: u8, chain_id: &[u8; 32]) -> NullifierSig {
    let kp = NullifierKeypair::from_seed(&[seed; 32]).unwrap();
    let (sig, _open) = s2c_sign(&kp, &[seed; 32], chain_id);
    sig
}

#[test]
fn publish_mine_scan_roundtrip() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let cid = chain.chain_id();

    let (start_height, _) = chain.tip().unwrap();

    // Publish a nullifier and a >80-byte genesis record in one transaction
    // (co-publication, S3), then mine it.
    let g = Genesis {
        version: 1,
        issuer_pk: NullifierKeypair::from_seed(&[9; 32]).unwrap().pk,
        mint_auth_key_hash: Digest::ZERO,
        policy: Policy {
            public_supply: true,
            freezable: true,
            max_supply: 0,
            decimals: 6,
        },
        ticker: "USDS".into(),
        name: "Test Dollar".into(),
        uri: "https://issuer.example/scsv".into(),
        extended_metadata_hash: [3u8; 32],
    };
    let issuer = NullifierKeypair::from_seed(&[9; 32]).unwrap();
    let rec = Record::genesis(&g);
    let sig = bip340_sign(&issuer, &rec.signing_message());
    let signed = SignedRecord {
        record: rec.clone(),
        sig,
    };

    let null = nsig(1, &cid);
    let payloads = vec![Payload::Nullifier(null), Payload::Record(signed.to_bytes())];
    let txid = chain.publish(&payloads).unwrap();
    chain.mine(1).unwrap();

    // locate finds it.
    let loc = chain.locate(&txid).unwrap().expect("tx confirmed");

    // scan finds both payloads at that location.
    let (tip_h, _) = chain.tip().unwrap();
    let blocks = chain.scan(start_height + 1, tip_h).unwrap();
    let found: Vec<_> = blocks
        .iter()
        .flat_map(|b| b.txs.iter())
        .filter(|t| t.txid == txid)
        .collect();
    assert_eq!(found.len(), 1, "our tx appears once");
    let tx = found[0];
    assert_eq!(tx.loc, loc, "scan and locate agree");
    assert_eq!(tx.payloads.len(), 2, "both payloads recovered");
    assert!(tx.payloads.contains(&Payload::Nullifier(null)));
    // The record payload round-trips to the same signed record.
    let rec_payload = tx
        .payloads
        .iter()
        .find_map(|p| match p {
            Payload::Record(b) => SignedRecord::from_bytes(b),
            _ => None,
        })
        .expect("record payload");
    assert_eq!(rec_payload, signed);
    assert!(rec_payload.verify(&g.issuer_pk));
}

#[test]
fn first_occurrence_wins_across_blocks() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let cid = chain.chain_id();
    let (start, _) = chain.tip().unwrap();

    // Same nullifier pk published in two different blocks; first wins.
    let dup = nsig(42, &cid);
    let first_txid = chain.publish(&[Payload::Nullifier(dup)]).unwrap();
    chain.mine(1).unwrap();
    let _second_txid = chain.publish(&[Payload::Nullifier(dup)]).unwrap();
    chain.mine(1).unwrap();

    let (tip, _) = chain.tip().unwrap();
    let blocks = chain.scan(start + 1, tip).unwrap();
    let mut idx = NullifierIndex::new();
    idx.apply_blocks(&blocks);

    let first_loc = chain.locate(&first_txid).unwrap().unwrap();
    assert_eq!(
        idx.first_occurrence(&dup.pk),
        Some(first_loc),
        "the earlier publication is the canonical one"
    );
}

#[test]
fn real_reorg_moves_first_occurrence() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let cid = chain.chain_id();

    // Publish a nullifier, mine it in a block, and record that block's hash.
    let target = nsig(77, &cid);
    let _txid = chain.publish(&[Payload::Nullifier(target)]).unwrap();
    let mined = chain.mine(1).unwrap();
    let block_with_tx = mined[0];
    let (h_before, _) = chain.tip().unwrap();

    let mut idx = NullifierIndex::new();
    idx.apply_blocks(&chain.scan(h_before, h_before).unwrap());
    assert_eq!(idx.first_occurrence(&target.pk).unwrap().height, h_before);

    // Invalidate that block: the nullifier's transaction returns to the
    // mempool and the tip rewinds by one.
    chain.invalidate_block(&block_with_tx).unwrap();
    let (h_after_invalidate, _) = chain.tip().unwrap();
    assert_eq!(h_after_invalidate, h_before - 1, "tip rewound one block");

    // Re-mine: the tx is included again at the (new) tip height. Rewind the
    // index above the fork point and replay — the real chain's first
    // occurrence is now the freshly mined block.
    let remined = chain.mine(1).unwrap();
    let (h_new, _) = chain.tip().unwrap();
    idx.rewind_above(h_after_invalidate);
    idx.apply_blocks(&chain.scan(h_after_invalidate + 1, h_new).unwrap());
    let loc = idx
        .first_occurrence(&target.pk)
        .expect("nullifier re-mined after reorg");
    assert_eq!(loc.height, h_new);
    // Sanity: the re-mined block differs from the invalidated one.
    assert_ne!(remined[0], block_with_tx);
}

#[test]
fn oversized_payload_is_rejected_before_broadcast() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    // A bundle whose encoding exceeds the node datacarrier size must be
    // rejected by us with a typed error, not sent and bounced by the node.
    let huge = Payload::Record(vec![0u8; scsv_testkit::regtest::DATACARRIER_SIZE + 10]);
    let err = chain.publish(&[huge]).unwrap_err();
    assert!(
        matches!(err, scsv_chain::ChainError::PayloadTooLarge(_)),
        "got {err:?}"
    );
}
