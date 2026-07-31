//! End-to-end wallet scenarios against a real spawned regtest node with real
//! full-parameter STARK proofs (`spec/19-WALLET.md`, `spec/16-RECEIVER.md`):
//!
//! * a chained A→B→C transfer where each recipient natively verifies the whole
//!   ancestry DAG plus every hop's balance/range proof;
//! * a double-spend (a stale wallet backup re-spends a coin) rejected on
//!   receive because the coin's deterministic nullifier already occurs earlier
//!   on-chain;
//! * a tamper matrix: one mutation per native receiver check, asserting the
//!   exact `RejectReason`.

use p3_field::PrimeCharacteristicRing;
use scsv_core::hash::Digest;
use scsv_core::types::{Genesis, Policy};
use scsv_core::F;

use scsv_wallet::receive::verify_bundle;
use scsv_wallet::{CoinBundle, RejectReason, Wallet, WalletError};

/// Confirmations required on every ancestry nullifier. Real depth logic (S6);
/// kept small so tests mine few blocks (proofs, not blocks, are the cost).
const CONF: u64 = 1;

fn secret(seed: u32) -> Digest {
    Digest([F::from_u32(seed); 8])
}

fn genesis_template() -> Genesis {
    Genesis {
        version: 1,
        issuer_pk: [0u8; 32], // create_asset overwrites this with the derived key
        mint_auth_key_hash: Digest::ZERO,
        policy: Policy {
            public_supply: true,
            freezable: false,
            max_supply: 0,
            decimals: 6,
        },
        ticker: "USDS".into(),
        name: "Test Dollar".into(),
        uri: "https://issuer.example/scsv".into(),
        extended_metadata_hash: [7u8; 32],
    }
}

#[test]
fn chained_a_b_c_receive() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let cid = chain.chain_id();

    let mut issuer = Wallet::new(secret(1001), cid);
    let mut alice = Wallet::new(secret(1002), cid);
    let mut bob = Wallet::new(secret(1003), cid);
    let mut carol = Wallet::new(secret(1004), cid);

    let asset = issuer
        .create_asset(&chain, genesis_template(), CONF)
        .unwrap();
    let asset_bytes = asset.to_bytes();

    // Mint 1_000_000 to Alice; Alice receives and verifies the mint bundle.
    let alice_addr = alice.new_address();
    let mint_bundle = issuer.mint(&chain, 1_000_000, alice_addr, CONF).unwrap();
    let got = alice.receive(&chain, &mint_bundle, CONF).unwrap();
    assert_eq!(got.amount, 1_000_000);
    assert_eq!(alice.balance(&asset_bytes), 1_000_000);

    // Alice → Bob: 600_000 (400_000 change stays with Alice).
    let bob_addr = bob.new_address();
    let to_bob = alice.send(&chain, 0, 600_000, bob_addr, CONF).unwrap();
    assert_eq!(to_bob.hops.len(), 2, "mint + alice's transfer");
    let bob_coin = bob.receive(&chain, &to_bob, CONF).unwrap();
    assert_eq!(bob_coin.amount, 600_000);
    assert_eq!(bob.balance(&asset_bytes), 600_000);
    assert_eq!(
        alice.balance(&asset_bytes),
        400_000,
        "alice keeps the change"
    );

    // Bob → Carol: 250_000 (350_000 change stays with Bob). Carol sees the full
    // three-hop ancestry (mint → alice → bob) and verifies every hop.
    let carol_addr = carol.new_address();
    let to_carol = bob.send(&chain, 0, 250_000, carol_addr, CONF).unwrap();
    assert_eq!(to_carol.hops.len(), 3, "mint + alice + bob");
    let carol_coin = carol.receive(&chain, &to_carol, CONF).unwrap();
    assert_eq!(carol_coin.amount, 250_000);
    assert_eq!(carol.balance(&asset_bytes), 250_000);
    assert_eq!(bob.balance(&asset_bytes), 350_000, "bob keeps the change");

    // Supply is conserved across the whole DAG.
    assert_eq!(
        alice.balance(&asset_bytes) + bob.balance(&asset_bytes) + carol.balance(&asset_bytes),
        1_000_000
    );
}

#[test]
fn double_spend_rejected_on_receive() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let cid = chain.chain_id();

    let mut issuer = Wallet::new(secret(2001), cid);
    let mut alice = Wallet::new(secret(2002), cid);
    let mut bob = Wallet::new(secret(2003), cid);
    let mut carol = Wallet::new(secret(2004), cid);

    let asset = issuer
        .create_asset(&chain, genesis_template(), CONF)
        .unwrap();
    let asset_bytes = asset.to_bytes();
    let alice_addr = alice.new_address();
    let mint_bundle = issuer.mint(&chain, 500_000, alice_addr, CONF).unwrap();
    alice.receive(&chain, &mint_bundle, CONF).unwrap();

    // A stale backup of Alice's wallet still believes the coin is unspent.
    let mut alice_backup = alice.clone();

    // Honest spend: Alice → Bob. Publishes the coin's nullifier at height L1.
    let to_bob = alice
        .send(&chain, 0, 500_000, bob.new_address(), CONF)
        .unwrap();
    // Malicious re-spend from the backup: Alice → Carol. Same coin, so the same
    // deterministic nullifier key is published again, now at a later height L2.
    let to_carol = alice_backup
        .send(&chain, 0, 500_000, carol.new_address(), CONF)
        .unwrap();

    // Bob (the first spend) verifies fine.
    assert_eq!(bob.receive(&chain, &to_bob, CONF).unwrap().amount, 500_000);
    assert_eq!(bob.balance(&asset_bytes), 500_000);

    // Carol's bundle cites L2 for the nullifier, but its first on-chain
    // occurrence is L1 — the double-spend is caught.
    let err = carol.receive(&chain, &to_carol, CONF).unwrap_err();
    assert!(
        matches!(
            err,
            WalletError::Rejected(RejectReason::NullifierWrongLocation)
        ),
        "expected NullifierWrongLocation, got {err:?}"
    );
    assert!(carol.coins().is_empty(), "carol took no coin");
}

#[test]
fn tamper_matrix() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let cid = chain.chain_id();

    let mut issuer = Wallet::new(secret(3001), cid);
    let mut alice = Wallet::new(secret(3002), cid);
    let mut bob = Wallet::new(secret(3003), cid);

    issuer
        .create_asset(&chain, genesis_template(), CONF)
        .unwrap();
    let alice_addr = alice.new_address();
    let mint_bundle = issuer.mint(&chain, 1_000_000, alice_addr, CONF).unwrap();
    alice.receive(&chain, &mint_bundle, CONF).unwrap();

    // One real transfer produces a bundle with a mint hop and a transfer hop;
    // every tamper case mutates a copy of it.
    let good = alice
        .send(&chain, 0, 600_000, bob.new_address(), CONF)
        .unwrap();
    verify_bundle(&good, &chain, CONF).expect("the untampered bundle verifies");

    let transfer = good.hops.len() - 1; // last hop is Alice's transfer
    let mint = 0; // first hop is the mint

    let reject = |b: &CoinBundle| verify_bundle(b, &chain, CONF).unwrap_err();

    // Wrong chain id.
    let mut b = good.clone();
    b.chain_id = [0xFF; 32];
    assert_eq!(reject(&b), RejectReason::ChainIdMismatch);

    // Mutated output amount: the recomputed essence hash no longer matches.
    let mut b = good.clone();
    b.hops[transfer].outputs[0].amount += 1;
    assert_eq!(reject(&b), RejectReason::TxHashMismatch);

    // Output that doesn't back-reference its creating hop.
    let mut b = good.clone();
    b.hops[transfer].outputs[0].out_index = 9;
    assert_eq!(reject(&b), RejectReason::BadOutputBackref);

    // Input not present among the ancestry hop's outputs.
    let mut b = good.clone();
    b.hops[transfer].inputs[0].null_pk = [1u8; 32];
    assert_eq!(reject(&b), RejectReason::InputNotInAncestry);

    // Nullifier public key disagrees with the input coin's committed key.
    let mut b = good.clone();
    b.hops[transfer].nullifiers[0].pk = [2u8; 32];
    assert_eq!(reject(&b), RejectReason::NullifierPkMismatch);

    // Sign-to-contract opening tampered: BIP340 still valid, binding broken.
    let mut b = good.clone();
    b.hops[transfer].nullifiers[0].s2c_r0[1] ^= 1;
    assert_eq!(reject(&b), RejectReason::S2cBindingFailed);

    // Corrupted balance proof bytes.
    let mut b = good.clone();
    b.hops[transfer].balance_proof = vec![0xAB; 32];
    assert_eq!(reject(&b), RejectReason::BalanceProofDecode);

    // Mint hop stripped of its record location.
    let mut b = good.clone();
    b.hops[mint].mint_record_loc = None;
    assert_eq!(reject(&b), RejectReason::MintRecordMissing);

    // Insufficient confirmations: demand far more depth than exists.
    assert_eq!(
        verify_bundle(&good, &chain, 100_000).unwrap_err(),
        RejectReason::InsufficientConfirmations
    );
}
