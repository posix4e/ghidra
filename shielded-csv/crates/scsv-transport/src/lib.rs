//! Signal payment transport: move coin bundles between wallets as attachments
//! through a real `signal-cli` daemon (JSON-RPC). Requires an operator-registered
//! Signal account; there is no mock. The transport-independent primitive is the
//! wallet's bundle export/import. See `spec/20-TRANSPORT.md`.

// Implemented in M9.
