//! Accounts and one-shot addresses (`spec/02-KEYS-ACCOUNTS.md`,
//! `spec/19-WALLET.md`).
//!
//! An account is a secret and its committed identity. A fresh address is
//! generated per expected payment: it carries a hiding commitment to the
//! account id plus the nullifier public key that will spend the coin received
//! there. The account keeps the address randomness and the nullifier secret.

use scsv_core::hash::Digest;
use scsv_core::types::{account_id, address};
use scsv_native_crypto::NullifierKeypair;

/// The secrets an account holds.
#[derive(Clone)]
pub struct Account {
    pub sk: Digest,
    pub id: Digest,
}

impl Account {
    /// Create an account from a 32-byte secret.
    pub fn from_secret(sk: Digest) -> Self {
        // v1: accountID commits to the secret. (The paper's S1 first-nullifier
        // binding is specific to its per-account-state nullifier; the v1 wallet
        // uses per-coin nullifiers, so double-spend is prevented per coin.)
        let id = account_id(&sk, &Digest::ZERO);
        Account { sk, id }
    }

    /// Derive the address secrets for a fresh payment, keyed by `nonce`.
    pub fn address(&self, nonce: u64) -> AddressSecret {
        // Address randomness and the nullifier context both derive from the
        // account secret and the nonce, so the whole address is recoverable
        // from (sk, nonce) — but nothing else can produce it.
        let mut r_in = [0u8; 40];
        r_in[..32].copy_from_slice(&self.sk.to_bytes());
        r_in[32..].copy_from_slice(&nonce.to_le_bytes());
        let addr_r = scsv_core::hash::h_sponge(
            scsv_core::hash::Domain::Addr,
            &scsv_core::codec::bytes_to_limbs16(&r_in),
        );
        let null_kp = NullifierKeypair::derive(&self.sk.to_bytes(), &addr_r.to_bytes());
        let addr = address(&self.id, &addr_r);
        AddressSecret {
            addr,
            addr_r,
            null_kp,
            nonce,
        }
    }
}

/// The secret side of an address, kept by the recipient.
#[derive(Clone)]
pub struct AddressSecret {
    pub addr: Digest,
    pub addr_r: Digest,
    pub null_kp: NullifierKeypair,
    pub nonce: u64,
}

impl AddressSecret {
    /// The shareable address handed to a payer.
    pub fn shareable(&self) -> ShareableAddress {
        ShareableAddress {
            addr: self.addr,
            null_pk: self.null_kp.pk,
        }
    }
}

/// The public address a payer needs: the coin commitment target and the
/// nullifier key that will spend the coin sent here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareableAddress {
    pub addr: Digest,
    pub null_pk: [u8; 32],
}

impl std::fmt::Display for ShareableAddress {
    /// Compact text form: `addr_hex:nullpk_hex`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.addr.to_hex(), hex::encode(self.null_pk))
    }
}

impl ShareableAddress {
    pub fn parse(s: &str) -> Option<ShareableAddress> {
        let (a, n) = s.split_once(':')?;
        let addr = Digest::from_bytes(&hex::decode(a).ok()?.try_into().ok()?)?;
        let null_pk: [u8; 32] = hex::decode(n).ok()?.try_into().ok()?;
        Some(ShareableAddress { addr, null_pk })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use scsv_core::F;

    #[test]
    fn addresses_are_deterministic_and_distinct() {
        let acct = Account::from_secret(Digest([F::from_u32(42); 8]));
        let a0 = acct.address(0);
        let a0b = acct.address(0);
        let a1 = acct.address(1);
        assert_eq!(a0.addr, a0b.addr);
        assert_eq!(a0.null_kp.pk, a0b.null_kp.pk);
        assert_ne!(a0.addr, a1.addr);
        assert_ne!(a0.null_kp.pk, a1.null_kp.pk);
    }

    #[test]
    fn shareable_roundtrip() {
        let acct = Account::from_secret(Digest([F::ONE; 8]));
        let s = acct.address(3).shareable();
        assert_eq!(ShareableAddress::parse(&s.to_string()).unwrap(), s);
    }
}
