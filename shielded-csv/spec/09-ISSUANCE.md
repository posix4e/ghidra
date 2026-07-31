# 09 · Issuance

**Job:** Define genesis, asset identity, and minting authority for permissionless issuance.

Uses `01-CRYPTO` hashing and the record chain of `08-RECORDS`.

Anyone can issue an asset. There is no registry; an asset is defined entirely by
its **genesis**:

```
Genesis {
  version:              u8,
  issuerPk:             XOnly,     // BIP340 x-only; may be a MuSig2 aggregate
  mintAuthKeyHash:      Digest,    // Poseidon2 key authorizing shielded mints;
                                   // MUST be 0 when publicSupply is set
  policy: Policy {
    publicSupply:       bool,      // spec 10
    freezable:          bool,      // spec 12
    maxSupply:          u64,       // 0 = unbounded
    decimals:           u8,
  },
  ticker:               String,
  name:                 String,
  uri:                  String,
  extendedMetadataHash: [u8; 32],
}
assetId = h_sponge(GenesisH, canonical_encoding(genesis))
```

Because `assetId` is the hash of the genesis, distinct policies or metadata are
distinct assets, and the identifier cannot be forged onto a different genesis.

## Minting authority

- **Shielded mints** (private assets): the minter proves knowledge of the secret
  whose hash is `mintAuthKeyHash`, in-circuit.
- **Public mints** (`publicSupply` assets): authority is the on-chain
  `issuerPk`, exercised by signing a MINT record (`08-RECORDS`). For these
  assets `mintAuthKeyHash` is required to be zero and the circuit enforces it
  (soundness item S4), so there is no hidden shielded-mint path.

Ticker/name collisions are out of protocol: wallets display `assetId`, and any
human-name binding is an out-of-band concern.
