# 10 · Public supply

**Job:** Define the public-mint discipline that makes an asset's supply auditable while transfers stay private.

Extends issuance (`09-ISSUANCE`) using records (`08-RECORDS`).

An asset with `policy.publicSupply = true` commits to publishing **every** unit
of supply on-chain in cleartext. Its genesis is itself published as record
`seq = 0`, and every mint is a MINT record.

## The binding

The circuit ties minted coins to their record so that supply cannot be inflated
in secret (soundness items S4, S5):

- A mint transaction takes the record's hash as a public input and constrains
  the created coins of that asset to equal `record.amount`.
- The record's `nullifierPk` equals the mint transaction's nullifier, so record
  and transaction are one-to-one, and they share a Bitcoin transaction (S3).
- Every downstream receiver (spec 16) re-checks these ties natively and
  additionally checks the running `cumulativeSupply` arithmetic and `maxSupply`
  bound. A coin of a public-supply asset that does not trace to a valid
  published mint record simply does not verify.

## What is and isn't public

Public: the genesis, every mint and burn (spec 11), key rotations, renounce,
metadata updates, and freeze updates — hence the exact total supply and the full
issuance timeline, computable from a Bitcoin node alone (spec 18).

Private: who holds the asset, individual balances, and the transfer graph. The
issuer's own distribution is private too — a public mint deposits into the
issuer's shielded treasury, and where it goes next is a normal shielded
transfer.
