#!/usr/bin/env bash
# The single acceptance gate: formatting, lints as errors, and the full test
# suite (which includes real STARK proofs and real regtest bitcoind nodes from
# M3 onward). CI and local development run exactly this.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.local/bin:$PATH"

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
