//! Scanned-block model and the nullifier first-occurrence index
//! (`spec/06-NULLIFIERS.md`, `spec/07-CHAIN-EMBEDDING.md`).
//!
//! These are pure functions over scanned blocks: the same block sequence always
//! yields the same index, and rewinding to a height then replaying is
//! idempotent — the property the reorg tests assert against a real node.

use std::collections::HashMap;

use scsv_core::types::ChainLoc;
use scsv_native_crypto::NullifierSig;

use crate::wire::Payload;

/// One SCSV payload located on the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedTx {
    pub loc: ChainLoc,
    pub txid: [u8; 32],
    /// All SCSV payloads carried by this transaction, in output order.
    pub payloads: Vec<Payload>,
}

/// A scanned block: its height, hash, and the SCSV-bearing transactions in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub txs: Vec<ScannedTx>,
}

/// First-occurrence index of nullifier public keys (`spec/06`). Built by
/// folding scanned blocks in order; a pk maps to the location of its *first*
/// on-chain occurrence, and later duplicates are ignored — this is the
/// double-spend rule.
#[derive(Clone, Debug, Default)]
pub struct NullifierIndex {
    first: HashMap<[u8; 32], (ChainLoc, NullifierSig)>,
    /// Height through which this index is valid.
    scanned_through: Option<u64>,
}

impl NullifierIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scanned_through(&self) -> Option<u64> {
        self.scanned_through
    }

    /// Fold a block into the index (blocks must be applied in height order).
    pub fn apply_block(&mut self, block: &ScannedBlock) {
        for tx in &block.txs {
            for p in &tx.payloads {
                if let Payload::Nullifier(sig) = p {
                    self.first.entry(sig.pk).or_insert((tx.loc, *sig));
                }
            }
        }
        self.scanned_through = Some(block.height);
    }

    /// Fold many blocks.
    pub fn apply_blocks(&mut self, blocks: &[ScannedBlock]) {
        for b in blocks {
            self.apply_block(b);
        }
    }

    /// The location of a pk's first occurrence, if any.
    pub fn first_occurrence(&self, pk: &[u8; 32]) -> Option<ChainLoc> {
        self.first.get(pk).map(|(loc, _)| *loc)
    }

    pub fn get(&self, pk: &[u8; 32]) -> Option<&(ChainLoc, NullifierSig)> {
        self.first.get(pk)
    }

    pub fn len(&self) -> usize {
        self.first.len()
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_empty()
    }

    /// Drop everything published above `height` (a reorg rewind). The caller
    /// then replays the new blocks. Because `first` stores the *lowest*
    /// location per pk, removing entries above `height` and replaying is
    /// equivalent to a fresh fold over the new chain.
    pub fn rewind_above(&mut self, height: u64) {
        self.first.retain(|_, (loc, _)| loc.height <= height);
        self.scanned_through = Some(height.min(self.scanned_through.unwrap_or(height)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nsig(pk: u8) -> NullifierSig {
        NullifierSig {
            pk: [pk; 32],
            sig: [0u8; 64],
        }
    }

    fn block(height: u64, txs: Vec<(u32, Vec<Payload>)>) -> ScannedBlock {
        ScannedBlock {
            height,
            hash: [height as u8; 32],
            txs: txs
                .into_iter()
                .map(|(tx_index, payloads)| ScannedTx {
                    loc: ChainLoc { height, tx_index },
                    txid: [tx_index as u8; 32],
                    payloads,
                })
                .collect(),
        }
    }

    #[test]
    fn first_occurrence_wins() {
        let mut idx = NullifierIndex::new();
        idx.apply_block(&block(10, vec![(1, vec![Payload::Nullifier(nsig(7))])]));
        idx.apply_block(&block(11, vec![(2, vec![Payload::Nullifier(nsig(7))])]));
        assert_eq!(
            idx.first_occurrence(&[7; 32]),
            Some(ChainLoc {
                height: 10,
                tx_index: 1
            })
        );
    }

    #[test]
    fn fold_is_order_deterministic_within_height() {
        // Two txs in the same block: lower tx_index wins.
        let mut idx = NullifierIndex::new();
        idx.apply_block(&block(
            5,
            vec![
                (0, vec![Payload::Nullifier(nsig(3))]),
                (1, vec![Payload::Nullifier(nsig(3))]),
            ],
        ));
        assert_eq!(
            idx.first_occurrence(&[3; 32]),
            Some(ChainLoc {
                height: 5,
                tx_index: 0
            })
        );
    }

    #[test]
    fn rewind_then_replay_is_idempotent() {
        let blocks = vec![
            block(1, vec![(0, vec![Payload::Nullifier(nsig(1))])]),
            block(2, vec![(0, vec![Payload::Nullifier(nsig(2))])]),
            block(3, vec![(0, vec![Payload::Nullifier(nsig(3))])]),
        ];
        let mut full = NullifierIndex::new();
        full.apply_blocks(&blocks);

        // Rewind above height 1, then replay 2..3 — must match the full fold.
        let mut rw = NullifierIndex::new();
        rw.apply_blocks(&blocks);
        rw.rewind_above(1);
        assert_eq!(rw.first_occurrence(&[2; 32]), None);
        rw.apply_blocks(&blocks[1..]);
        assert_eq!(
            rw.first_occurrence(&[2; 32]),
            full.first_occurrence(&[2; 32])
        );
        assert_eq!(
            rw.first_occurrence(&[3; 32]),
            full.first_occurrence(&[3; 32])
        );
        assert_eq!(rw.len(), full.len());
    }

    #[test]
    fn reorg_can_move_first_occurrence() {
        // pk 9 first appears at height 3, then after a reorg replaces heights
        // >=2, it appears at height 2 — the index must reflect the new chain.
        let mut idx = NullifierIndex::new();
        idx.apply_blocks(&[
            block(1, vec![]),
            block(2, vec![]),
            block(3, vec![(0, vec![Payload::Nullifier(nsig(9))])]),
        ]);
        assert_eq!(idx.first_occurrence(&[9; 32]).unwrap().height, 3);
        idx.rewind_above(1);
        idx.apply_blocks(&[
            block(2, vec![(0, vec![Payload::Nullifier(nsig(9))])]),
            block(3, vec![]),
        ]);
        assert_eq!(idx.first_occurrence(&[9; 32]).unwrap().height, 2);
    }
}
