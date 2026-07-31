# 21 · Comparisons

**Job:** State precisely where this implementation follows and departs from the Shielded CSV paper.

The paper is Nick, Eagen, Linus — "Shielded CSV: Private and Efficient
Client-Side Validation", IACR eprint 2025/068.

## Followed

- Bitcoin as a pure ordered publication layer; ~64-byte nullifiers; all
  validation client-side (`00-OVERVIEW`).
- Account model with per-transaction nullifier keys and a spent accumulator
  (`02-KEYS-ACCOUNTS`, `04-STATE`).
- Sign-to-contract Schnorr nullifiers with first-occurrence-wins
  (`06-NULLIFIERS`).
- Two-step init/finalize payment flow (`05-TRANSACTIONS`).

## Departures

| Topic | Paper | Here |
|---|---|---|
| Issuance | out of scope | permissionless genesis, `assetId = H(genesis)` (`09-ISSUANCE`) |
| Supply transparency | not addressed | per-asset public-supply policy with record chain (`10-PUBLIC-SUPPLY`), provable burns (`11-BURNS`) |
| Compliance powers | none | opt-in freeze (`12-FREEZE`) and seizure (`13-SEIZURE`) |
| Proof system | abstract PCD; recursive SNARKs/folding suggested | hand-written AIR, Plonky3 uni-stark, Poseidon2-BabyBear (`14-AIR-STATEMENT`) |
| Receive cost | O(1) via recursion | chained ancestry DAG, linear in deduped history (`15-PROOF-BUNDLES`); recursion deferred |
| Account identity | accountID is a Schnorr key | accountID binds accountSk and the first nullifier key hash (S1, `02-KEYS-ACCOUNTS`) |
| Publisher fees | trustless fee-coin mechanism | deferred; publisher is a funded node wallet (`17-PUBLISHER`) |
| Transport | out of scope | Signal via signal-cli (`20-TRANSPORT`) |

## Relation to prior asset protocols

Versus RGB/Taproot-Assets-style client-side validation: same chain-as-ordering
philosophy, but transfers here carry zero-knowledge proofs instead of plaintext
history, and the public-supply/freeze/seizure policy set targets the regulated
stablecoin case explicitly.
