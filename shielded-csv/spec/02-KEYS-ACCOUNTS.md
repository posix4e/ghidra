# 02 · Keys and accounts

**Job:** Define account identity and the per-transaction nullifier key that authorizes each state update.

Hashing and encodings are from `01-CRYPTO`.

## Account identity

An account has a long-lived secret `accountSk`. Its identity binds the secret to
the **first** nullifier public-key hash the account will ever use:

```
accountID = h_sponge(AccountId, accountSk_limbs ‖ firstNullifierPkHash)
```

This binding is the fix for the account-fork double-spend (soundness item S1):
because the first nullifier key is fixed into the identity, an owner cannot
stand up two different initial states for the same `accountID`, so the
chain's first-occurrence rule (spec 06) resolves to a single history.

## Nullifier keys

Each transaction uses a **fresh** nullifier keypair. The account state commits
to the current `nullifierPkHash`; knowledge of the corresponding secret is what
authorizes the next state update, and the new state commits to the next key's
hash. Nullifier keys are hash-based inside the circuit; their on-chain
secp256k1 counterpart used for the published nullifier is a separate object
defined later in the nullifier spec (06).

## Addresses

An address is a hiding commitment to the recipient's `accountID`:

```
addr = h_sponge(Addr, accountID ‖ addr_r)
```

with fresh randomness `addr_r` per expected payment. The address *is* the coin's
recipient field (spec 03); only the holder of `accountSk` and `addr_r` can
open it, which is what the spend proof does.
