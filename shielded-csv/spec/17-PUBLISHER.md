# 17 · Publisher

**Job:** Define how nullifiers and records get funded and landed on the chain.

Publishes the payloads of `06-NULLIFIERS` and `08-RECORDS` via
`07-CHAIN-EMBEDDING`.

A publisher takes payloads and turns them into confirmed Bitcoin transactions.
In v1 the publisher is simply a funded Bitcoin Core wallet driven over RPC: it
builds a transaction with one OP_RETURN output per payload, funds it, signs it,
and broadcasts it. On regtest the same wallet mines the confirming blocks.

Protocol rules the publisher must respect:

- A MINT/BURN record and the nullifier it binds MUST be outputs of the **same**
  Bitcoin transaction (S3).
- Batching unrelated payloads into one transaction is allowed and expected;
  ordering within a block is given by transaction index and output order.

Publishers are untrusted: they can censor or delay, but cannot forge —
signatures and first-published-wins do the rest. The trustless publisher fee
mechanism from the paper (publisher appends its address and mints a fee coin)
is deferred (spec 99); on regtest the publisher is the test harness
itself and fees are ordinary node-wallet fees.
