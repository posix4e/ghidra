//! The transport-independent payment primitive end to end: a real bundle from a
//! regtest transfer is written to a `.scvb` file, read back, and accepted by the
//! recipient — the same bytes every transport (Signal included) ultimately
//! moves (`spec/20-TRANSPORT.md`).

use p3_field::PrimeCharacteristicRing;
use scsv_core::hash::Digest;
use scsv_core::types::{Genesis, Policy};
use scsv_core::F;
use scsv_transport::{export_bundle, import_bundle};
use scsv_wallet::Wallet;

const CONF: u64 = 1;

fn secret(seed: u32) -> Digest {
    Digest([F::from_u32(seed); 8])
}

fn genesis() -> Genesis {
    Genesis {
        version: 1,
        issuer_pk: [0u8; 32],
        mint_auth_key_hash: Digest::ZERO,
        policy: Policy {
            public_supply: true,
            freezable: false,
            max_supply: 0,
            decimals: 2,
        },
        ticker: "GIFT".into(),
        name: "Gift Card".into(),
        uri: "https://issuer.example/gift".into(),
        extended_metadata_hash: [1u8; 32],
    }
}

#[test]
fn bundle_file_moves_a_real_payment() {
    let node = scsv_testkit::shared_node();
    let chain = node.chain();
    let cid = chain.chain_id();

    let mut issuer = Wallet::new(secret(7_100_001), cid);
    let mut alice = Wallet::new(secret(7_100_002), cid);
    let mut bob = Wallet::new(secret(7_100_003), cid);

    let asset = issuer.create_asset(&chain, genesis(), CONF).unwrap();
    let mint = issuer
        .mint(&chain, 10_000, alice.new_address(), CONF)
        .unwrap();
    alice.receive(&chain, &mint, CONF).unwrap();

    // Alice pays Bob; the resulting bundle is the payment.
    let bundle = alice
        .send(&chain, 0, 4_000, bob.new_address(), CONF)
        .unwrap();

    // Move it purely as a file — no wallet-to-wallet channel.
    let path = std::env::temp_dir().join(format!("scsv-pay-{}.scvb", std::process::id()));
    export_bundle(&bundle, &path).unwrap();
    let imported = import_bundle(&path).unwrap();
    assert_eq!(imported, bundle, "the file round-trips exactly");

    // Bob accepts the imported bundle just as if handed it directly.
    let coin = bob.receive(&chain, &imported, CONF).unwrap();
    assert_eq!(coin.amount, 4_000);
    assert_eq!(bob.balance(&asset.to_bytes()), 4_000);

    let _ = std::fs::remove_file(&path);
}
