# 18 · Audit

**Job:** Define how anyone computes an asset's supply and history from the chain alone.

Folds the record chain (`08-RECORDS`) under the rules of `10-PUBLIC-SUPPLY`,
`11-BURNS`, `12-FREEZE`, and `13-SEIZURE`.

The audit is a pure function of scanned chain data — no cooperation from the
issuer or any holder is needed.

For each asset (identified by its on-chain GENESIS record):

1. Walk its records in chain order, keeping the **first** record per `seq` and
   ignoring later duplicates (equivocations are reported as anomalies).
2. Verify each record's signature against the issuer key current at that point
   (following ROTATE-KEY records; nothing after a RENOUNCE mints).
3. For MINTs: check the hash link, `cumulativeSupply` arithmetic, `maxSupply`
   bound, and that the bound nullifier is on-chain in the same transaction.
4. For BURNs: subtract only if the referenced burn proof is available and
   verifies (`11-BURNS`); otherwise flag and keep supply conservative-high.
5. For SEIZEs: subtract only if the frozen-handle precondition held and the
   evidence pack verifies (`13-SEIZURE`); enforce seized-handle monotonicity
   against later FREEZE-UPDATEs.
6. Maintain the frozen set from FREEZE-UPDATE records (delta availability
   flagged when missing).

Output: current supply, the full mint/burn/seize timeline with heights, the
current frozen set, issuer key history, and an anomaly list (equivocation,
broken links, bad arithmetic, orphan records, unavailable proofs/deltas).

The engine lives in `scsv-asset::audit` and is surfaced as `scsv audit`.
