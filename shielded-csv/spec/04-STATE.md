# 04 · State

**Job:** Define account state and the indexed-Merkle accumulators it commits to.

Builds on `01-CRYPTO`, `02-KEYS-ACCOUNTS`, `03-COINS`.

## Account state

```
AccountState {
  accountID:       Digest,   // 02-KEYS-ACCOUNTS
  nullifierPkHash: Digest,   // authorizes the next update (02)
  spentRoot:       Digest,   // accumulator of spent coinIDs
  balancesRoot:    Digest,   // per-asset running balance (bookkeeping)
  seq:             u64,      // monotonic state counter
}
stateCommitment = h_sponge(StateCom, accountID ‖ nullifierPkHash ‖ spentRoot ‖ balancesRoot ‖ seq)
```

Exactly one state per account is live at a time; each transaction advances
`seq` by one and rotates the nullifier key.

## Indexed Merkle trees

`spentRoot`, `balancesRoot`, and the per-asset frozen sets (spec 12) are all
**indexed (sorted) Merkle trees** of depth 32. Each leaf stores `(key, nextKey,
nextIndex)` linking it to the next-larger key, which gives cheap
**non-membership** proofs: to show `k` is absent, open the leaf whose
`key < k < nextKey`. Insertion updates that low leaf and appends the new leaf.

Depth is 32 everywhere, including tests — there are no reduced parameters.

The reference tree, its insert/non-membership witnesses, and the leaf hashing
live in `scsv-core`; a property test checks it against a `BTreeSet` model.
