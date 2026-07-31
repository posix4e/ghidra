# 12 · Freeze

**Job:** Define the frozen set and the in-circuit non-membership that blocks frozen handles from being spent.

For assets with `policy.freezable` (`09-ISSUANCE`); updates via records
(`08-RECORDS`); trees from `04-STATE`.

A freezable asset's issuer maintains a **frozen set** of handles that may not be
spent. A handle is either an `accountID` or a `coinID` (`03-COINS`).

## Representation

The frozen set is an indexed Merkle tree (`04-STATE`) over handles. Each change
is a FREEZE-UPDATE record `{ newFrozenRoot, deltaHash }`; the delta contents are
hosted off-chain and hash-anchored, so an issuer that stops serving its deltas
bricks its own asset's spendability — availability is thereby forced, and anyone
may mirror.

## Enforcement

A transfer of a freezable asset proves, in-circuit, **non-membership** of the
spender's `accountID` and of each input `coinID` against a public `frozenRoot`
(one indexed-tree non-membership per handle). A frozen handle cannot produce a
verifying transfer.

## Freshness

The `frozenRoot` a transfer proves against must be the one current at the
transaction's nullifier height, within a ±6-block grace window (matching the
confirmation depth of `06-NULLIFIERS`). Receivers check this natively
(spec 16). Freezing takes effect for future transfers only; it does not
retroactively invalidate coins already received.

Discovering which handle to freeze is out of band — shielded transfers hide
addresses, so the issuer learns handles from KYC, redemption, or reports. The
mechanism is in-protocol; the discovery is not.
