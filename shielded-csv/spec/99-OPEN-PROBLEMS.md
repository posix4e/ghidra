# 99 · Open problems

**Job:** Record what is deliberately deferred or unsolved, and the shape of each gap.

- **Recursion / O(1) receive.** Bundles are linear in deduped ancestry
  (`15-PROOF-BUNDLES`). The verifier boundary and single public-input schema
  are recursion-shaped so a recursive verifier can replace DAG verification
  without protocol changes. Deferred until real bundle-size data demands it.
- **Multi-asset transactions.** One asset per transaction today
  (`05-TRANSACTIONS`); lifting it needs per-asset balance vectors and a
  variable schedule.
- **Half-aggregation.** Publishers currently post one signature per nullifier;
  CISA half-aggregation would compress batches toward the paper's 64-byte/tx
  figure (`17-PUBLISHER`).
- **Mainnet-realistic embedding.** OP_RETURN with raised datacarrier policy is
  honest on regtest but not mainnet-standard for our sizes
  (`07-CHAIN-EMBEDDING`); the real target is the nullifier riding inside a
  taproot key-spend signature via sign-to-contract.
- **Publisher fee market.** The paper's trustless fee-coin mechanism
  (`17-PUBLISHER`) is unimplemented.
- **Seed recovery.** Fundamentally unavailable in client-side validation
  (`19-WALLET`); the practical ceiling is deterministic key derivation plus
  snapshot backups.
- **MuSig2 ceremonies.** Aggregate issuer keys work today as plain x-only keys;
  an in-tool multi-party signing flow does not exist.
- **Static donation addresses.** Addresses are one-shot commitments
  (`02-KEYS-ACCOUNTS`); a reusable-address scheme without linkability is open,
  as in the paper.
- **Freeze-grace race.** A handle frozen at height `h` can still be spent in
  transactions whose nullifiers land within the ±6-block grace
  (`12-FREEZE`) — accepted by design; receivers may locally tighten.
- **External audit.** The proof parameters and the whole construction are
  unaudited (`00-OVERVIEW`).
