# 05 · Transactions

**Job:** Define the transaction value model and the two-step init/finalize lifecycle.

Builds on `03-COINS` and `04-STATE`.

A transaction moves an account from a previous state and input coins to a new
state and output coins:

```
Transaction: (PrevState, PrevCoins) -> (NewState, NewCoins)
```

## Value model (v1)

A single transaction touches **one asset** (multi-asset transactions are
deferred; see spec 99). Value is conserved per asset:

```
sum(input amounts) + mintAmount = sum(output amounts) + burnAmount
```

`mintAmount` is non-zero only for issuance transactions (spec 09),
`burnAmount` only for burns (spec 11). Amounts are range-checked as 3-limb
`u64` values so the sum cannot silently overflow the field.

## Lifecycle

1. **Init.** The sender builds the new state and coins, chooses a fresh nullifier
   key, updates the spent accumulator, and produces a STARK proof of the whole
   statement with the transaction hash held at zero. This can happen before the
   nullifier is confirmed.
2. **Publish.** The sender hands the nullifier to a publisher (spec 17),
   which lands it on the chain (spec 07).
3. **Finalize.** Once the nullifier is confirmed at a known location, the sender
   re-proves the same statement with the real transaction hash bound in, giving
   the **finalize** proof.
4. **Deliver.** The sender sends each recipient their output coin plus the proof
   bundle (spec 15) off-chain.

Only finalize proofs appear in delivered bundles; the init/finalize distinction
is enforced in-circuit (soundness item S8).
