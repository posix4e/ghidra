//! The transport-independent payment primitive: a coin bundle on disk.
//!
//! A `.scvb` file is exactly `CoinBundle::to_bytes()` — the postcard encoding of
//! the coin and its ancestry. Any channel that can move a file (Signal, email,
//! a USB stick) moves a payment. Every transport in this crate is a wrapper
//! around these two functions.

use std::io;
use std::path::Path;

use scsv_wallet::CoinBundle;

/// The conventional extension for an exported bundle ("Shielded CSV Value
/// Bundle").
pub const BUNDLE_EXT: &str = "scvb";

/// Write a bundle to `path` (its postcard bytes, verbatim).
pub fn export_bundle(bundle: &CoinBundle, path: &Path) -> io::Result<()> {
    std::fs::write(path, bundle.to_bytes())
}

/// Read a bundle from `path`, returning `InvalidData` if the bytes don't decode.
pub fn import_bundle(path: &Path) -> io::Result<CoinBundle> {
    let bytes = std::fs::read(path)?;
    CoinBundle::from_bytes(&bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a valid coin bundle"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scsv_wallet::{CoinBundle, WireCoin, WireHop};

    fn sample_bundle() -> CoinBundle {
        let coin = WireCoin {
            asset_id: [1; 32],
            amount: 42,
            addr: [2; 32],
            null_pk: [3; 32],
            creating_tx_hash: [9; 32],
            out_index: 0,
        };
        let hop = WireHop {
            tx_hash: [9; 32],
            asset_id: [1; 32],
            salt: 5,
            is_mint: true,
            inputs: vec![],
            outputs: vec![coin],
            nullifiers: vec![],
            mint_record_loc: None,
            balance_proof: vec![],
        };
        CoinBundle {
            chain_id: [0xAB; 32],
            hops: vec![hop],
            target_tx_hash: [9; 32],
            target_out_index: 0,
        }
    }

    #[test]
    fn roundtrip_through_a_file() {
        let bundle = sample_bundle();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("scsv-bundle-{}.{BUNDLE_EXT}", std::process::id()));
        export_bundle(&bundle, &path).unwrap();
        let back = import_bundle(&path).unwrap();
        assert_eq!(back, bundle);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn garbage_file_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("scsv-garbage-{}.{BUNDLE_EXT}", std::process::id()));
        std::fs::write(&path, b"not a bundle").unwrap();
        assert!(import_bundle(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
