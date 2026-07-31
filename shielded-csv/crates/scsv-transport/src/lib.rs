//! Signal payment transport (`spec/20-TRANSPORT.md`).
//!
//! A coin bundle is a self-contained byte string ([`scsv_wallet::CoinBundle`]),
//! so moving a payment is just moving those bytes. Two layers:
//!
//! * [`bundle_file`] — the transport-independent primitive: write a bundle to a
//!   `.scvb` file and read it back. This is what every transport ultimately
//!   moves, and it is fully testable with no network.
//! * [`signal`] — a real JSON-RPC client to a `signal-cli` daemon (HTTP mode):
//!   send a bundle as a message attachment, and poll for received bundles. There
//!   is no mock daemon; live send/receive needs an operator-registered Signal
//!   account (see `ci/install-signal-cli.sh` and the `SCSV_SIGNAL_*` env in the
//!   CLI). The request/response framing is unit-tested without a daemon.

pub mod bundle_file;
pub mod signal;

pub use bundle_file::{export_bundle, import_bundle, BUNDLE_EXT};
pub use signal::{ReceivedBundle, SignalConfig, SignalTransport, TransportError};
