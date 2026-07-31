# 16 · Receiver

**Job:** Define exactly what a wallet checks before accepting an incoming coin.

Verifies bundles (`15-PROOF-BUNDLES`) against the chain (`07-CHAIN-EMBEDDING`),
records (`08-RECORDS`, `10-PUBLIC-SUPPLY`), and freeze state (`12-FREEZE`).

The receiver is the native half of soundness: everything the AIR cannot see
(chain ordering, records, freshness) is enforced here. Verification of a bundle
proceeds:

1. **Structure.** Parse; check magic/version/chain id; hop `txHash` uniqueness;
   topologically sort (reject cycles); all link targets present.
2. **Chain readiness.** The wallet's scan must cover the highest referenced
   height plus 6 confirmations (S6) with no pending reorg below it.
3. **Per hop, in topological order:**
   - STARK verify with the public-input–binding wrapper (S2).
   - Nullifier: first occurrence of `pk` is exactly this hop's claimed
     location; BIP340 signature valid; sign-to-contract opening recomputes `R`
     against this hop's `txHash`; ≥ 6 confirmations.
   - Public-input cross-checks: `txHash` matches; `isInit = 0`; `numInputs`
     matches the link tuples; `inputsDigest` recomputes; each parent's
     `outputsCommitment` and `outIndex` bound.
   - State edge: parent hop's `newStateCom` equals this hop's `prevStateCom`,
     or the hop is a valid initial state under the S1 account-id rule.
   - Asset/policy: resolve the genesis (on-chain for public assets, in-bundle
     preimage otherwise); policy bits match (S4). For mint hops: the MINT
     record exists at `recordLoc`, won first-published-wins, matches `pk` and
     amount, shares the Bitcoin transaction with the nullifier (S3), and its
     `cumulativeSupply`/`maxSupply` arithmetic holds (S5).
   - Freeze freshness: for freezable assets, the proof's `frozenRoot` is one
     valid in `[h-6, h]` for the hop's nullifier height `h`.
4. **Target coin.** The opening hashes to a leaf that Merkle-verifies against
   the final hop's `outputsCommitment`; the address opens to one of the
   wallet's own issued addresses; the `coinID` is not already held; for
   freezable assets the handle is not currently frozen.

Any failure yields a typed rejection naming the failed check — the tamper test
matrix asserts each one. Accepted coins are demoted to pending if a later reorg
invalidates any ancestor fact.
