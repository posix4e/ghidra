# 20 · Transport

**Job:** Define how coin bundles move between wallets over Signal.

Moves the bundles of `15-PROOF-BUNDLES` produced/consumed by the wallet
(`19-WALLET`).

Payments are messages. The v1 transport is **Signal**, driven through a real
`signal-cli` daemon speaking JSON-RPC; the wallet's file export/import remains
the transport-independent primitive underneath.

## Mechanics

- The sender attaches the bundle bytes as a Signal attachment with a small
  envelope note (magic, version, bundle hash) and sends it to the recipient's
  Signal address.
- `scsv listen` runs a receive loop against the daemon: new envelope →
  download attachment → full receiver verification (`16-RECEIVER`) → accept
  into the wallet → acknowledge. Duplicate envelopes are deduplicated by bundle
  hash.
- Signal provides end-to-end encryption and delivery; it never learns bundle
  contents beyond size/timing, and nothing about the chain.

## Accounts

`signal-cli` requires a real registered Signal account (phone-number
registration or device linking). Registration is an operator step, documented in
the README; the daemon's account is configured per wallet. Transport tests run
against real Signal servers whenever operator-registered test accounts are
provided via environment configuration; the rest of the system is fully testable
without Signal through file export/import.

The JSON-RPC client and receive loop live in `scsv-transport`;
`ci/install-signal-cli.sh` installs the pinned daemon.
