# 03 · Coins

**Job:** Define what a coin is and how it names its asset, amount, and recipient.

Uses hashing from `01-CRYPTO` and addresses from `02-KEYS-ACCOUNTS`.

A **coin** is the unit of value transferred between accounts:

```
Coin {
  assetId:        Digest,     // which asset (spec 09)
  amount:         u64,        // 3-limb in-circuit (01-CRYPTO)
  addr:           Address,    // hiding commitment to the recipient (02)
  creatingTxHash: TxHash,     // the transaction that created this coin
  outIndex:       u32,        // its position among that tx's outputs
  nullifierLoc:   ChainLoc,   // where the creating tx's nullifier was published
}
```

The coin's identity is

```
coinID = h_sponge(CoinLeaf-derived, creatingTxHash_limbs ‖ outIndex)
```

`coinID` is what the spent accumulator (spec 04) records and what freeze
handles (spec 12) name. `creatingTxHash` and `nullifierLoc` let a receiver
locate and check the coin's creating hop on the chain.

A coin is spent by being consumed as a transaction input; the spender proves it
can open `addr` to its own `accountID`. Coins are never mutated — a transfer
consumes input coins and creates fresh output coins.
