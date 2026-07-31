# 19 · Wallet

**Job:** Define what a wallet stores, its operations, and the backup reality.

Drives transactions (`05-TRANSACTIONS`), scanning (`07-CHAIN-EMBEDDING`),
receiving (`16-RECEIVER`), and issuer operations (`09-ISSUANCE` through
`13-SEIZURE`).

## Stored state

- Account: `accountSk`, current state preimage and its latest finalize proof,
  the account's full spent tree (witnesses are recomputed from it, never cached
  stale), current nullifier secret and the queued next keypair.
- Coins: each unspent coin's fields, opening randomness, output-leaf path, and
  content-addressed references into a hop store (`hops/<txHash>.bin`) holding
  the deduplicated ancestry packages that back its bundle.
- Assets: known genesis preimages, the record-chain view snapshot, cached
  frozen trees for freezable assets (rebuildable pure functions of the chain).
- Addresses: issued `addr -> addr_r` map. Pending: init proofs awaiting
  confirmation. Chain cursor: last scanned height/hash and nullifier index.

Persistence is a versioned directory: small JSON for structure, raw bytes for
proofs, atomic tmp+rename writes. Export/import is a snapshot of the directory.

## Operations

`create_account`, `new_address`, `create_asset`, `mint`, `send_init`,
`send_finalize`, `receive`, `scan` (with reorg demotion), `audit_supply`, and
issuer ops `freeze / seize / rotate_issuer_key / renounce`, plus the reporter-side
evidence-pack export (`13-SEIZURE`).

## No seed recovery

There is **no seed-based recovery**. The chain stores only nullifiers; state
preimages, coin openings, ancestry proofs, and address randomness exist solely
in this wallet. Losing the wallet directory loses the funds even if the account
secret survives. Backups are whole-directory snapshots, taken after every
state-changing operation.
