# 07 · Chain embedding

**Job:** Define how nullifiers and records are written to and read from Bitcoin.

Carries the nullifiers of `06-NULLIFIERS` and the records defined next (spec 08).

Bitcoin is the ordered publication layer. This implementation embeds payloads as
**OP_RETURN** outputs of real, wallet-funded transactions on a real Bitcoin Core
node — there is no mock and no fallback.

## Payloads

Each published Bitcoin transaction carries a **bundle** of one or more payloads
inside a single OP_RETURN output (a `count` then length-framed payloads); each
payload is tagged with the 4-byte magic `SCSV`, a version byte, and a kind byte:

- **Nullifier** payloads (`06-NULLIFIERS`).
- **Record** payloads (spec 08), which for mints/burns MUST share the same
  Bitcoin transaction as the nullifier they bind to (soundness item S3) — a
  single-output bundle satisfies this trivially.

One output rather than several also sidesteps Bitcoin Core's refusal to build a
transaction with multiple `data` outputs via `createrawtransaction`.

Nullifier and typical record payloads exceed Bitcoin's default 80-byte
OP_RETURN standardness limit, so the node is run with an explicit larger
`-datacarriersize`. This is a regtest/instance policy choice; the
mainnet-realistic alternative of hiding the nullifier inside a taproot key-spend
signature is deferred (spec 99).

## Locations and reorgs

A `ChainLoc` is `(height, txIndex)`. Scanning walks blocks in order, parses
`SCSV` OP_RETURN outputs, and folds them into the nullifier index and record
views. A block-hash mismatch against the last-scanned hash signals a reorg,
which rewinds the affected height range and replays; downstream views are
reorg-rewindable. Reorg handling is exercised with a real node via
`invalidateblock`/`reconsiderblock`.

The RPC client, publisher funding, block parsing, and reorg detection live in
`scsv-chain::BitcoindChain`.
