# 13 · Seizure

**Job:** Define destroy-and-reissue of frozen handles, with evidence discipline mirroring provable burns.

Depends on freeze (`12-FREEZE`) and burns (`11-BURNS`); records per `08-RECORDS`.

Seizure is the destroy-and-reissue power a regulated stablecoin needs (the
analogue of Tether's `destroyBlackFunds`). It reuses the freeze machinery and
the evidence discipline of provable burns, and costs **nothing** in-circuit — it
is entirely native record rules.

## Preconditions and rule

A SEIZE record `{ coinID, amount, evidencePackHash }` is valid only if:

- the handle is **already in the frozen set** at the time of seizure, and
- its `evidencePackHash` resolves to an available evidence pack — the seized
  coin's opening plus a full verified proof bundle (spec 15),
  supplied by whoever reported/froze the coin — that proves the coin's `amount`
  and ties it to this asset.

Only then does the audit (spec 18) subtract the seized amount. Absent
evidence, supply stays conservative-high while the freeze remains in force, so a
seizure can never be used to secretly deflate supply.

## Monotonicity

Seized handles are **monotone**: a later FREEZE-UPDATE that removes a seized
handle from the frozen set is treated as invalid by the record view — its root
never becomes current, which breaks the issuer's own freeze chain. Resurrecting
seized funds is therefore not possible without abandoning the asset.

Replacement funds, if any, are ordinary auditable public mints
(`10-PUBLIC-SUPPLY`). A seizure discloses the seized coin's ancestry graph via
its evidence pack.
