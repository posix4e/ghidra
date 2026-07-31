# Shielded CSV for Bitcoin

A from-scratch implementation of **Shielded CSV** — private client-side
validation anchored to Bitcoin (Nick/Eagen/Linus, IACR eprint 2025/068) — with
permissionless asset issuance, an opt-in **public-supply** policy for
Tether-style auditable stablecoins (public mints/burns, provable burns, freeze
and seizure), and transaction validity proven by a **hand-written AIR** over
BabyBear (Plonky3 uni-stark + Poseidon2). No zkVM.

Everything runs against real infrastructure: the chain layer is a real Bitcoin
Core node (regtest for tests and demos), proofs use the one real parameter set,
and payment transport is real `signal-cli`. There are no mocks and no fallback
code paths.

```
on-chain:   ~64-byte nullifiers  +  cleartext issuance records (public assets)
off-chain:  coins + STARK proof bundles, wallet to wallet (Signal)
audit:      anyone with a Bitcoin node can compute exact supply
privacy:    amounts, holders, and the transfer graph never leave the wallets
```

## Layout

| Path | What |
|---|---|
| `spec/` | The protocol, in dependency-numbered files. Start at `spec/00-OVERVIEW.md`. |
| `crates/scsv-core` | Field, Poseidon2, indexed Merkle trees, protocol types. |
| `crates/scsv-native-crypto` | BIP340 + sign-to-contract (native only, never in-circuit). |
| `crates/scsv-air` | The transaction AIR and STARK prove/verify. |
| `crates/scsv-chain` | Real Bitcoin Core RPC: publish, scan, reorg handling. |
| `crates/scsv-asset` | Issuance, record chains, supply audit. |
| `crates/scsv-wallet` | Wallet, receiver verification, persistence. |
| `crates/scsv-transport` | Signal transport via signal-cli. |
| `crates/scsv-cli` | The `scsv` binary. |
| `crates/scsv-testkit` | Regtest node harness, trace mutation, spec lint. |
| `crates/scsv-demos` | End-to-end scenarios (Tether demo, double-spend, reorg…). |

## 1. Install prerequisites

```sh
# pinned, checksum-verified Bitcoin Core into ~/.local/bin
bash ci/install-bitcoind.sh
export PATH="$HOME/.local/bin:$PATH"
```

Rust 1.94.1 is pinned by `rust-toolchain.toml`. Signal transport additionally
needs `ci/install-signal-cli.sh` and a registered Signal account (arrives in
M9; see `spec/20-TRANSPORT.md`).

## 2. Check

```sh
bash ci/check.sh   # fmt + clippy -D warnings + full test suite
```

The test suite spawns real regtest bitcoind nodes and produces real
full-parameter STARK proofs — a missing `bitcoind` is a hard failure, not a
skip.

## 3. Demo

```sh
cargo run -p scsv-cli -- demo tether   # from M8: full stablecoin lifecycle on live regtest
```

## Status

Research software, unaudited, protocol version 1 under active construction.
Build order and per-milestone verification: M1 scaffold → M2 primitives → M3
chain → M4 AIR → M5 issuance → M6 freeze+seizure → M7 wallet → M8 demos → M9
Signal. Known-deferred items live in `spec/99-OPEN-PROBLEMS.md`.
