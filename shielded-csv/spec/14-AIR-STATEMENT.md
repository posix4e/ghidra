# 14 · AIR statement

**Job:** State, normatively, the transaction compliance predicate and its public-input schema — the single source the prover, verifier, and negative tests all cite.

This is the heart of the protocol. It composes every prior spec: keys
(`02-KEYS-ACCOUNTS`), coins (`03-COINS`), state (`04-STATE`), transactions
(`05-TRANSACTIONS`), nullifiers (`06-NULLIFIERS`), issuance (`09-ISSUANCE`),
public supply (`10-PUBLIC-SUPPLY`), burns (`11-BURNS`), freeze (`12-FREEZE`),
and seizure (`13-SEIZURE`).

One **unified AIR** proves every transaction kind (transfer / mint / burn, init
/ finalize, freezable or not) as flag-gated paths of the same table. One table
means one verification key and one public-input schema.

## Trace shape

Each row is one Poseidon2-16 permutation (`01-CRYPTO`) plus routing columns:
phase selectors, schedule counters, a small digest register file, Merkle
routing, balance accumulators, key-comparison aux, and shared range-check bits
(~600 columns). A typical two-input transfer is on the order of 512 rows.

## Constraint groups

Poseidon2 rounds; hash-schedule routing; Merkle path consistency; indexed-tree
non-membership; spent-accumulator insert chain; per-asset balance conservation;
nullifier-key binding and spend authorization (including the S1 account-id
opening on initial states); state commitment in/out with `seq` increment;
cross-hop input binding; outputs commitment (with per-leaf randomness, S7);
record binding for mint/burn; genesis/policy branching (S4); freeze
non-membership (`12-FREEZE`); range checks; and init/finalize discipline (S8).

## Public inputs (99 field elements, ordered)

`schemaVersion(1) · kindBits(1) · assetId(8) · prevStateCom(8) · newStateCom(8)
· nullifierPk(16) · txHash(16) · outputsCommitment(8) · inputsDigest(8) ·
numInputs(1) · numOutputs(1) · recordHash(8) · mintAmount(3) · burnAmount(3) ·
frozenRoot(8) · frozenRootHeight(1) · policyBits(1)`.

`kindBits` packs `isInit / isMint / isBurn / isInitState`. `txHash` is zero in
init proofs. `inputsDigest` is a Poseidon2 chain over the cleartext link tuples
carried in the bundle, which the receiver recomputes.

## Fiat–Shamir binding (S2)

The prove/verify wrapper observes `h_sponge` of the canonical public-input
vector into the challenger **before** sampling any challenge, so a proof cannot
be replayed against altered public inputs regardless of upstream behavior.

The reference AIR is `scsv-air::air`; the trace builder that must mirror it
exactly is `scsv-air::schedule`.
