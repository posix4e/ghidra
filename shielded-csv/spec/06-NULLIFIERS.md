# 06 · Nullifiers

**Job:** Define the on-chain nullifier, its sign-to-contract construction, and the double-spend rule.

A **nullifier** is the only per-transaction object published on Bitcoin. It is a
secp256k1 BIP340 Schnorr public key plus a signature, verified **natively** by
scanners and receivers and never inside the AIR.

## Sign-to-contract

The signature commits to the transaction hash by tweaking the nonce. For a
fresh nonce `k` with `R0 = k·G`:

```
R = R0 + H_tag("SCSV/s2c", R0.x ‖ txHash)·G
```

and the account signs a fixed protocol message with nonce `R`. The pair
`(nullifierPk, sig)` therefore binds to `txHash` while occupying only ~64 bytes
of effective payload (a 32-byte key and a 32-byte `R`). The opening value `R0`
travels in the proof bundle so a receiver can recompute `R` and confirm the tie
to the hop's transaction hash.

## Double-spend rule

Scanning the chain, a wallet inserts `nullifierPk -> location` the **first** time
it sees each key and ignores later duplicates. Because an account spends by
revealing a nullifier key committed by its previous state, a second spend from
the same state would have to republish the same key — which is never accepted.
First occurrence wins.

First-occurrence is evaluated relative to the current best chain; a reorg can
change it, so acceptance requires confirmations (soundness item S6, detailed in
the receiver spec, 16).

The BIP340 + sign-to-contract primitives live in `scsv-native-crypto`.
