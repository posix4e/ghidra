//! The wallet: accounts, coins, issuer operations, transaction building, the
//! receive-side verifier, and persistence (`spec/19-WALLET.md`).
//!
//! Every chain interaction goes through a real `BitcoindChain`. Publishing a
//! transfer puts only a nullifier on-chain; the coin and its ancestry travel
//! off-chain in a `CoinBundle`. There is no seed recovery: the wallet directory
//! is the only backup.

use std::collections::HashMap;

use scsv_air::transfer::{prove_transfer, Slot};
use scsv_asset::evidence::MemoryEvidence;
use scsv_chain::records::{Record, RecordBody, SignedRecord};
use scsv_chain::wire::Payload;
use scsv_chain::{BitcoindChain, ChainError, PublicationChain};
use scsv_core::hash::Digest;
use scsv_core::types::Genesis;
use scsv_native_crypto::{bip340_sign, s2c_sign, NullifierKeypair};

use crate::account::{Account, AddressSecret, ShareableAddress};
use crate::hop::{
    essence_tx_hash, CoinBundle, Loc, OutputEssence, WireCoin, WireHop, WireNullifier,
};
use crate::receive::{verify_bundle, RejectReason};

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("not an issuer")]
    NotIssuer,
    #[error("coin index out of range")]
    NoSuchCoin,
    #[error("coin already spent")]
    AlreadySpent,
    #[error("insufficient coin value")]
    Insufficient,
    #[error("published transaction did not confirm")]
    Unconfirmed,
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("proof: {0}")]
    Proof(String),
    #[error("rejected on receive: {0:?}")]
    Rejected(RejectReason),
}

/// A coin the wallet owns, with the material needed to spend it and its full
/// ancestry (so it can be forwarded).
#[derive(Clone)]
pub struct OwnedCoin {
    pub coin: WireCoin,
    /// The nonce of the address that received this coin (re-derives its
    /// nullifier key).
    pub addr_nonce: u64,
    pub ancestry: Vec<WireHop>,
    pub spent: bool,
}

/// Issuer state for a wallet that created an asset.
#[derive(Clone)]
pub struct IssuerState {
    pub kp: NullifierKeypair,
    pub genesis: Genesis,
    pub last_hash: Digest,
    pub seq: u64,
    pub supply: u64,
    pub evidence: MemoryEvidence,
}

#[derive(Clone)]
pub struct Wallet {
    pub account: Account,
    pub chain_id: [u8; 32],
    next_nonce: u64,
    /// addr bytes -> the nonce that produced it.
    issued: HashMap<[u8; 32], u64>,
    coins: Vec<OwnedCoin>,
    issuer: Option<IssuerState>,
}

impl Wallet {
    pub fn new(secret: Digest, chain_id: [u8; 32]) -> Self {
        Wallet {
            account: Account::from_secret(secret),
            chain_id,
            next_nonce: 0,
            issued: HashMap::new(),
            coins: Vec::new(),
            issuer: None,
        }
    }

    /// Issue a fresh one-shot address.
    pub fn new_address(&mut self) -> ShareableAddress {
        self.fresh_address().shareable()
    }

    fn fresh_address(&mut self) -> AddressSecret {
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        let secret = self.account.address(nonce);
        self.issued.insert(secret.addr.to_bytes(), nonce);
        secret
    }

    pub fn coins(&self) -> &[OwnedCoin] {
        &self.coins
    }

    /// Unspent balance of an asset.
    pub fn balance(&self, asset_id: &[u8; 32]) -> u64 {
        self.coins
            .iter()
            .filter(|c| !c.spent && &c.coin.asset_id == asset_id)
            .map(|c| c.coin.amount)
            .sum()
    }

    pub fn issuer_state(&self) -> Option<&IssuerState> {
        self.issuer.as_ref()
    }

    /// Become the issuer of a new asset, publishing its genesis record.
    pub fn create_asset(
        &mut self,
        chain: &BitcoindChain,
        genesis: Genesis,
        confirmations: u64,
    ) -> Result<Digest, WalletError> {
        let kp = NullifierKeypair::from_seed(&self.account.sk.to_bytes())
            .map_err(|_| WalletError::Proof("issuer key".into()))?;
        let genesis = Genesis {
            issuer_pk: kp.pk,
            ..genesis
        };
        let rec = Record::genesis(&genesis);
        let last_hash = rec.record_hash();
        let sig = bip340_sign(&kp, &rec.signing_message());
        let signed = SignedRecord { record: rec, sig };
        chain.publish(&[Payload::Record(signed.to_bytes())])?;
        chain.mine(confirmations)?;
        let asset_id = genesis.asset_id();
        self.issuer = Some(IssuerState {
            kp,
            genesis,
            last_hash,
            seq: 0,
            supply: 0,
            evidence: MemoryEvidence::new(),
        });
        Ok(asset_id)
    }

    /// Mint `amount` of the wallet's asset to `to`, publishing the MINT record
    /// co-published with its nullifier. Returns the minted coin's bundle.
    pub fn mint(
        &mut self,
        chain: &BitcoindChain,
        amount: u64,
        to: ShareableAddress,
        confirmations: u64,
    ) -> Result<CoinBundle, WalletError> {
        let (tx_hash, salt, out_coin, payloads) = {
            let iss = self.issuer.as_mut().ok_or(WalletError::NotIssuer)?;
            let asset_id = iss.genesis.asset_id().to_bytes();
            iss.seq += 1;
            let salt = iss.seq;
            let out_ess = OutputEssence {
                asset_id,
                amount,
                addr: to.addr.to_bytes(),
                null_pk: to.null_pk,
            };
            let tx_hash = essence_tx_hash(salt, true, &asset_id, &[], &[out_ess]);
            let out_coin = WireCoin {
                asset_id,
                amount,
                addr: to.addr.to_bytes(),
                null_pk: to.null_pk,
                creating_tx_hash: tx_hash,
                out_index: 0,
            };
            let mint_null = NullifierKeypair::derive(&iss.kp.secret_bytes(), &tx_hash);
            let (nsig, _open) = s2c_sign(&mint_null, &tx_hash, &self.chain_id);
            iss.supply += amount;
            let rec = Record {
                asset_id: iss.genesis.asset_id(),
                seq: iss.seq,
                prev_record_hash: iss.last_hash,
                body: RecordBody::Mint {
                    amount,
                    cumulative_supply: iss.supply,
                    nullifier_pk: mint_null.pk,
                },
            };
            iss.last_hash = rec.record_hash();
            let sig = bip340_sign(&iss.kp, &rec.signing_message());
            let signed = SignedRecord { record: rec, sig };
            (
                tx_hash,
                salt,
                out_coin,
                vec![Payload::Record(signed.to_bytes()), Payload::Nullifier(nsig)],
            )
        };

        let txid = chain.publish(&payloads)?;
        chain.mine(confirmations)?;
        let loc = chain.locate(&txid)?.ok_or(WalletError::Unconfirmed)?;

        let hop = WireHop {
            tx_hash,
            asset_id: out_coin.asset_id,
            salt,
            is_mint: true,
            inputs: vec![],
            outputs: vec![out_coin],
            nullifiers: vec![],
            mint_record_loc: Some(loc.into()),
            balance_proof: vec![],
        };
        let bundle = CoinBundle {
            chain_id: self.chain_id,
            hops: vec![hop.clone()],
            target_tx_hash: tx_hash,
            target_out_index: 0,
        };
        self.maybe_own(out_coin, vec![hop]);
        Ok(bundle)
    }

    /// Send `amount` of a held coin to `to`. Publishes the input's nullifier,
    /// proves conservation, and returns the recipient's bundle. Change (if any)
    /// stays in the wallet.
    pub fn send(
        &mut self,
        chain: &BitcoindChain,
        coin_index: usize,
        amount: u64,
        to: ShareableAddress,
        confirmations: u64,
    ) -> Result<CoinBundle, WalletError> {
        let owned = self
            .coins
            .get(coin_index)
            .ok_or(WalletError::NoSuchCoin)?
            .clone();
        if owned.spent {
            return Err(WalletError::AlreadySpent);
        }
        let v = owned.coin.amount;
        if amount > v {
            return Err(WalletError::Insufficient);
        }
        let asset_id = owned.coin.asset_id;
        let change = v - amount;
        let change_addr = self.fresh_address();

        let recip_ess = OutputEssence {
            asset_id,
            amount,
            addr: to.addr.to_bytes(),
            null_pk: to.null_pk,
        };
        let change_ess = OutputEssence {
            asset_id,
            amount: change,
            addr: change_addr.addr.to_bytes(),
            null_pk: change_addr.null_kp.pk,
        };
        let input_id = owned.coin.coin_id();
        let outs_ess: Vec<OutputEssence> = if change > 0 {
            vec![recip_ess, change_ess]
        } else {
            vec![recip_ess]
        };
        let tx_hash = essence_tx_hash(0, false, &asset_id, &[input_id], &outs_ess);

        let recip_coin = WireCoin {
            asset_id,
            amount,
            addr: to.addr.to_bytes(),
            null_pk: to.null_pk,
            creating_tx_hash: tx_hash,
            out_index: 0,
        };
        let change_coin = WireCoin {
            asset_id,
            amount: change,
            addr: change_addr.addr.to_bytes(),
            null_pk: change_addr.null_kp.pk,
            creating_tx_hash: tx_hash,
            out_index: 1,
        };

        // Spend the input: sign its nullifier (deterministic per coin) bound to
        // this tx hash, and publish it.
        let null_kp = self.account.address(owned.addr_nonce).null_kp;
        let (nsig, opening) = s2c_sign(&null_kp, &tx_hash, &self.chain_id);
        let txid = chain.publish(&[Payload::Nullifier(nsig)])?;
        chain.mine(confirmations)?;
        let loc = chain.locate(&txid)?.ok_or(WalletError::Unconfirmed)?;

        // Prove conservation over the revealed amounts.
        let mut slots = vec![
            Slot {
                amount: v,
                is_out: false,
            },
            Slot {
                amount,
                is_out: true,
            },
        ];
        if change > 0 {
            slots.push(Slot {
                amount: change,
                is_out: true,
            });
        }
        let (proof, _pub) =
            prove_transfer(&slots).map_err(|e| WalletError::Proof(e.to_string()))?;
        let balance_proof =
            postcard::to_allocvec(&proof).map_err(|e| WalletError::Proof(e.to_string()))?;

        let wire_null = WireNullifier {
            pk: nsig.pk,
            sig: nsig.sig,
            s2c_r0: opening.r0,
            loc: Loc::from(loc),
        };
        let outputs = if change > 0 {
            vec![recip_coin, change_coin]
        } else {
            vec![recip_coin]
        };
        let hop = WireHop {
            tx_hash,
            asset_id,
            salt: 0,
            is_mint: false,
            inputs: vec![owned.coin],
            outputs,
            nullifiers: vec![wire_null],
            mint_record_loc: None,
            balance_proof,
        };

        let mut hops = owned.ancestry.clone();
        hops.push(hop.clone());
        let bundle = CoinBundle {
            chain_id: self.chain_id,
            hops: hops.clone(),
            target_tx_hash: tx_hash,
            target_out_index: 0,
        };

        // Mark input spent; keep the change coin.
        self.coins[coin_index].spent = true;
        if change > 0 {
            self.coins.push(OwnedCoin {
                coin: change_coin,
                addr_nonce: change_addr.nonce,
                ancestry: hops,
                spent: false,
            });
        }
        Ok(bundle)
    }

    /// Verify an incoming bundle and, if its target is addressed to us, take
    /// ownership of the coin. Returns the received coin.
    pub fn receive(
        &mut self,
        chain: &BitcoindChain,
        bundle: &CoinBundle,
        confirmations: u64,
    ) -> Result<WireCoin, WalletError> {
        let verified =
            verify_bundle(bundle, chain, confirmations).map_err(WalletError::Rejected)?;
        let coin = verified.coin;
        if let Some(&nonce) = self.issued.get(&coin.addr) {
            if !self.coins.iter().any(|c| c.coin == coin) {
                self.coins.push(OwnedCoin {
                    coin,
                    addr_nonce: nonce,
                    ancestry: bundle.hops.clone(),
                    spent: false,
                });
            }
        }
        Ok(coin)
    }

    fn maybe_own(&mut self, coin: WireCoin, ancestry: Vec<WireHop>) {
        if let Some(&nonce) = self.issued.get(&coin.addr) {
            self.coins.push(OwnedCoin {
                coin,
                addr_nonce: nonce,
                ancestry,
                spent: false,
            });
        }
    }
}
