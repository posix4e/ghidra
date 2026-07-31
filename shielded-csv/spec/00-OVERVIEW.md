# 00 · Overview

**Job:** State what Shielded CSV (this implementation) is and map the specification.

Shielded CSV is a private, client-side-validation asset protocol anchored to
Bitcoin. Bitcoin is used only as an ordered publication layer: the sole data
that ever touches the chain is a stream of ~64-byte **nullifiers** and, for
assets that opt into public supply, cleartext **issuance records**. All
transaction validity is established off-chain by STARK proofs that wallets
exchange directly with one another. Nobody but the sender and receiver of a
payment learns its amount, addresses, or that it happened at all.

This implementation follows the Shielded CSV paper (Nick, Eagen, Linus — IACR
eprint 2025/068) and adds three things the paper leaves open:

1. **Permissionless issuance.** Anyone can define an asset; its identifier is
   the hash of its genesis. There is no registry and no gatekeeper.
2. **Optional public supply.** An asset can commit, at genesis, to publishing
   every mint and burn on-chain in cleartext, so that its total supply is
   auditable by anyone running a Bitcoin node — while transfers stay shielded.
   This is the Tether-style stablecoin use case. Such assets also support issuer
   **freeze** and **seizure** of specific coins/accounts.
3. **Hand-written AIR proofs.** The compliance predicate is proven with a
   custom AIR over BabyBear using Plonky3's uni-stark and Poseidon2 — no zkVM.

Everything runs against real infrastructure: a real Bitcoin Core node for the
chain layer and real `signal-cli` for payment transport. There are no mocks.

## Contents

- `01` — Crypto: field, Poseidon2 instance, domain separation.
- `02` — Keys and accounts: account identity and the per-transaction nullifier key.
- `03` — Coins: what a coin is and how it commits to a recipient.
- `04` — State: account state and the indexed-Merkle accumulators.
- `05` — Transactions: the init/finalize lifecycle and value model.
- `06` — Nullifiers: the sign-to-contract construction and double-spend rule.
- `07` — Chain embedding: how records and nullifiers ride on Bitcoin.
- `08` — Records: the per-asset issuer record chain wire format.
- `09` — Issuance: genesis, asset identity, minting authority.
- `10` — Public supply: the public-mint discipline and its guarantees.
- `11` — Burns: provable burns and conservative-high accounting.
- `12` — Freeze: the frozen set and in-circuit non-membership.
- `13` — Seizure: destroy-and-reissue for frozen handles.
- `14` — AIR statement: the normative compliance predicate and public inputs.
- `15` — Proof bundles: the ancestry-DAG wire format.
- `16` — Receiver: how a wallet verifies an incoming coin.
- `17` — Publisher: batching nullifiers onto the chain.
- `18` — Audit: computing supply from the chain alone.
- `19` — Wallet: stored state, operations, and the no-seed-recovery reality.
- `20` — Transport: moving bundles over Signal.
- `21` — Comparisons: how this differs from the paper.
- `99` — Open problems: what is deferred and why.
- Glossary: terms of art.

## Status

Research software. Unaudited. The proof parameters target a conjectured
≥100-bit security level but have not been independently reviewed.
