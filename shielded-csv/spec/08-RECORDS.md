# 08 · Records

**Job:** Define the per-asset issuer record chain and its wire format.

Records ride on the chain per `07-CHAIN-EMBEDDING`.

A **record** is an issuer-signed statement about an asset. Records for one asset
form a hash-linked chain ordered by a sequence number, with
**first-published-wins** per `(assetId, seq)`: if an issuer equivocates, Bitcoin
ordering picks the winner and the loser is ignored.

## Wire format

```
magic "SCSV" | version:u8 | kind:u8 | bodyLen:u16 | body | issuerSig:64
```

`issuerSig` is a BIP340 signature over a tagged hash of the body by the asset's
current issuer key. Kinds:

| kind | name            | body (summary)                                             |
|------|-----------------|------------------------------------------------------------|
| 1    | GENESIS         | the full genesis (spec 09); this is `seq = 0`               |
| 2    | MINT            | `seq, prevHash, amount, cumulativeSupply, nullifierPk`     |
| 3    | BURN            | mint fields + `burnProofHash` (spec 11)                            |
| 4    | SEIZE           | `coinID, amount, evidencePackHash` (spec 13)                  |
| 5    | ROTATE-KEY      | `newIssuerPk` (signed by the old key)                      |
| 6    | RENOUNCE        | freezes minting authority forever                          |
| 7    | METADATA-UPDATE | `newExtendedMetadataHash`                                   |
| 8    | FREEZE-UPDATE   | `newFrozenRoot, deltaHash` (spec 12)                                 |

`cumulativeSupply` carries a running total so that supply can be checked
incrementally. The MINT/BURN `nullifierPk` ties the record to exactly one
transaction, since a nullifier key appears on-chain at most once.

The first-wins fold, hash-linking, and reorg-rewindable record view live in
`scsv-asset::RecordChainView`.
