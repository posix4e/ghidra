//! Test support for Shielded CSV: the real-`bitcoind` regtest harness
//! (`RegtestNode`, added in M3), the AIR trace mutator (M4), scenario builders,
//! and the spec-numbering lint.
//!
//! The regtest harness spawns a real Bitcoin Core node — there is no mock and no
//! skip path; a missing `bitcoind` is a hard panic pointing at
//! `ci/install-bitcoind.sh`.

pub mod spec_lint;
