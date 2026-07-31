# 11 · Burns

**Job:** Define provable burns and the conservative-high accounting rule.

Extends public supply (`10-PUBLIC-SUPPLY`); records per `08-RECORDS`.

Burning removes supply. Unlike a mint — whose honesty every receiver enforces —
a burn has no receiver to check it, so a dishonest issuer could understate
liabilities by claiming burns that never happened. This implementation requires
burns to be **provable**.

## Rule

A BURN record carries a `burnProofHash`. The burn counts toward supply reduction
only if that hash resolves to an **available** STARK proof whose revealed public
inputs show:

- the destroyed `amount`,
- that it is bound to this asset and this record.

The proof is hosted off-chain; only its 32-byte hash is on-chain.

If the proof is unavailable or fails to verify, the audit (spec 18) does
**not** subtract the burn. Supply then reads **conservative-high** — the safe
direction for a liability audit, since it never understates what is owed.

The burn proof shares the transaction-level statement of `05-TRANSACTIONS`
(inputs consumed, nothing of that asset created); the burn-specific reveal is
part of the AIR public inputs (spec 14).
