# 15 · Proof bundles

**Job:** Define the wire format that carries a coin's ancestry DAG of proofs.

Bundles carry the proofs of `14-AIR-STATEMENT` for transactions
(`05-TRANSACTIONS`) whose nullifiers (`06-NULLIFIERS`) sit on the chain
(`07-CHAIN-EMBEDDING`).

Receiving a coin means verifying its entire ancestry. The v1 model is
**chained**: the bundle contains one hop package per ancestor transaction,
deduplicated (shared ancestors appear once).

```
CoinBundle {
  magic "SCVB" | version:u8,
  chainId: [u8;32],
  hops: [HopPackage],           // topologically sortable, deduped by txHash
  targets: [TargetCoin],
}

HopPackage {
  txHash:        [u8;32],
  publicInputs:  [F; 99],        // 14-AIR-STATEMENT
  starkProof:    bytes,
  nullifier:     { pk, sig, s2cOpeningR0, loc },   // 06-NULLIFIERS
  linkTuples:    [{ parentTxHash, outIndex, parentOutputsCommitment }],
  stateParent:   Option<txHash>, // hop that produced prevStateCom; None = initial state
  recordLoc:     Option<ChainLoc>, // mint/burn hops (08-RECORDS)
}

TargetCoin {
  finalHopTx: [u8;32],
  outIndex:   u32,
  opening:    { assetId, amount, addr, leafRandomness, merklePath },
}
```

Link tuples are cleartext; the receiver recomputes `inputsDigest` from them.
Bundle size is linear in the deduped ancestry (each hop proof is roughly
100–400 KB); the receiving cost model and its consequences are stated in
`00-OVERVIEW` and revisited in spec 99 (recursion).

Encoding is canonical hand-rolled bytes (little-endian lengths, fixed field
order) — the same bytes are hashed wherever a bundle is referenced by hash
(e.g. seizure evidence packs, `13-SEIZURE`).
