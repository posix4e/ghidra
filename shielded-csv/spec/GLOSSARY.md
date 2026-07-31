# Glossary

- **AIR** — Algebraic Intermediate Representation: the constraint system a
  STARK proves over an execution trace.
- **Bundle** — the wire object carrying a coin plus its ancestry DAG of hop
  proofs.
- **Chain location (`ChainLoc`)** — `(block height, transaction index)` of a
  published payload.
- **Coin** — a unit of value: asset, amount, address commitment, and provenance
  pointers.
- **coinID** — hash of `(creatingTxHash, outIndex)`; the coin's name in
  accumulators and freeze handles.
- **Evidence pack** — the coin opening + verified bundle that makes a seizure
  count in the audit.
- **First-published-wins** — the rule that the first on-chain occurrence (of a
  nullifier key, or of a record's `(assetId, seq)`) is canonical and later
  duplicates are ignored.
- **Freeze handle** — an `accountID` or `coinID` placed in a freezable asset's
  frozen set.
- **Genesis** — the document defining an asset; its hash is the `assetId`.
- **Hop** — one transaction in a coin's ancestry, with its proof and nullifier.
- **Indexed Merkle tree** — sorted-leaf Merkle tree with next-pointers giving
  non-membership proofs.
- **Init / finalize proof** — the pre-confirmation proof (txHash zeroed) and the
  post-confirmation re-proof (txHash bound); only finalize proofs travel.
- **Nullifier** — the per-transaction secp256k1 key + sign-to-contract signature
  published on Bitcoin; double-spend prevention.
- **Public input** — a field element the STARK verifier sees; the 99-element
  schema is fixed protocol-wide.
- **Publisher** — whoever funds and broadcasts the Bitcoin transaction carrying
  payloads.
- **Record** — an issuer-signed, hash-linked, on-chain statement about an asset
  (mint, burn, seize, rotate, renounce, metadata, freeze update).
- **Sign-to-contract (s2c)** — committing to a message inside a Schnorr nonce:
  `R = R0 + H(R0.x ‖ m)·G`.
- **Spent accumulator** — the account's indexed tree of consumed coinIDs.
- **Supply (audited)** — mints minus proven burns minus proven seizures, per the
  chain alone; conservative-high under missing evidence.
