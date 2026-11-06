//! Proving a retained row stale from the seal order of its pages.
//!
//! The AAD binds page id and kind and no commit id. A page overwritten after a
//! row's commit therefore still authenticates under that row, and `begin_read_at`
//! returns newer bytes with no error. The envelope's nonce counter can show this.
//!
//! # The proof
//!
//! Take row `C` and a later commit `D` with a root id that differs from `C`'s
//! root of the same tree.
//!
//! - Every root assignment in `btree::tree` names a page the same session
//!   allocated and wrote. So a changed root id means `D`'s root was sealed after
//!   `C`'s header landed. No tree collapses onto an older child.
//! - Every tree write is copy-on-write onto a fresh id. Only a rekey reseals a
//!   page in place, and it does so under a non-zero epoch.
//! - One writer lock orders flushes, and one generator serves them. Its counter
//!   only rises for committed pages, across restarts too. Every commit header
//!   carries an anchor covering its pages, and `MainDbNonceGen::recover` resumes
//!   past that anchor by the largest budget any run can use.
//!
//! So each page of an intact `C` holds a counter below `D`'s root. A page at or
//! above that counter was sealed after `C`, and row `C` names bytes it never held.
//! A delta page is verbatim, so it keeps the producer's prefix and counter.
//!
//! The roots of both trees bound both trees, because one generator seals them.
//! The nearest such commit gives the tightest bound. A row whose roots match the
//! later row's inherits that row's bound. The newest row's later commit is the
//! live root pair.
//!
//! A newer row whose own root was overwritten can hold a bound that proves too
//! much. That row is itself stale. The prefix rule removes every row older than
//! a stale row anyway, so this never removes a row the rule keeps.
//!
//! # What voids it
//!
//! The scan reports nothing, and prunes nothing, when the store cannot show order:
//!
//! - **Epoch above zero.** A rekey reseals in walk order. Rows survive a rekey.
//! - **Any walked page under another epoch, cipher, or identity.** A store in the
//!   middle of a rekey shows this.
//! - **`PlaintextMac`.** Its tag does not cover the nonce, so a counter is unproved.
//! - **An observer handle.** A live writer moves pages during the walk.
//!
//! These do not void it:
//!
//! - **A main repack.** It resets every row, so no row spans its reseal order. A
//!   segment-only repack keeps rows and writes catalog pages copy-on-write.
//! - **A fork.** It starts with no rows.
//! - **A follower's own seals.** They carry a per-open random prefix, and a walked
//!   page under another identity voids the scan. No walk reaches them. Free-list
//!   chain pages carry kind `Free`, so they fail as a node. A relocated history
//!   tree lands at or above the allocation cursor, past every row's `next_page_id`.
//!   The scan reads the history tree's rows through ordinary reads, and its pages
//!   never enter the ledger.
//!
//! # The one path this cannot exclude
//!
//! A byte copy of `main.db` that takes an apply, then commits as `Standalone`,
//! mixes two counter streams in one tree. A local root can then hold a counter
//! below a delta page it was sealed after, so an intact row can look stale.
//!
//! An apply now stamps an unstamped store `FOLLOWER` before any delta page lands,
//! so such a copy refuses `Standalone`. The residue is a copy that took an apply
//! under an older release and then committed. That release wrote no stamp, so no
//! header field shows the mix. A snapshot of that copy carries it too. The check
//! can report and prune an intact row on such a store.
//!
//! # What stays undetectable
//!
//! - A page overwritten in the flush of the bound's own commit, sealed before that
//!   bound's root. Flushes run in page-id order, so a lower page id seals first.
//! - For the newest row, any page sealed before the current live root. A follower
//!   holds no root of a commit between its restore and its latest apply. This is
//!   the weakest case. An older row's bound was sealed before the restore, so
//!   every later seal exceeds it.
//! - Every row on a store with an epoch above zero, for good, once a rekey runs.
//! - A page returned to older genuine bytes, since its counter goes back with it.
//!
//! An apply whose delta holds no pages skips the scan.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use bytes::Bytes;

use crate::Result;
use crate::btree::BTree;
use crate::btree::tree::seals::{SealLedger, SealedPage};
use crate::crypto::CipherId;
use crate::errors::PagedbError;
use crate::recovery::history_report::{
    HistorySealVerdict, SealOrderVoid, StaleHistoryRow, StaleRowEvidence,
};
use crate::txn::db::catalog::history_policy::proves_unreadable_pages;
use crate::txn::db::core::{CommitHistoryMeta, Db, WriterState, decode_commit_meta};
use crate::txn::mode::DbMode;
use crate::vfs::Vfs;

use super::history::history_row_commit;

/// Rows read per batch while a deep walk or a rekey scans them.
const HISTORY_ROW_BATCH: usize = 512;

/// A page of a row sealed at or after a later commit's root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResealEvidence {
    pub page: SealedPage,
    pub later_root: SealedPage,
}

/// One newest-to-oldest pass over a store's rows.
pub(crate) struct HistorySealScan {
    ledger: SealLedger,
    /// The roots of the nearest later commit, data tree first.
    later_roots: [u64; 2],
    /// The lowest later root seen. It bounds every older row too.
    bound: Option<SealedPage>,
    void: Option<SealOrderVoid>,
}

impl HistorySealScan {
    /// Why this scan proves nothing, if it does.
    pub(crate) fn void(&self) -> Option<SealOrderVoid> {
        self.void
    }
}

impl<V: Vfs + Clone> Db<V> {
    /// Why this handle's store cannot show seal order, read from its state alone.
    fn seal_order_void(&self) -> Option<SealOrderVoid> {
        if self.mode == DbMode::Observer {
            Some(SealOrderVoid::ObserverHandle)
        } else if self.mk_epoch.load(Ordering::SeqCst) > 0 {
            Some(SealOrderVoid::RekeyedEpoch)
        } else if self.cipher_id == CipherId::PlaintextMac {
            Some(SealOrderVoid::UnauthenticatedNonce)
        } else {
            None
        }
    }

    /// Start a scan. The caller excludes writers until the scan ends, and holds
    /// no dirty main page, because these reads go past the cache.
    pub(crate) fn begin_history_seal_scan(&self, state: &WriterState) -> HistorySealScan {
        HistorySealScan {
            ledger: SealLedger::new(&self.file_id),
            later_roots: [state.root_page_id, state.catalog_root_page_id],
            bound: None,
            void: self.seal_order_void(),
        }
    }

    /// Walk one row, then compare the newest seal it reaches against its bound.
    /// Returns the pages this scan read first under the row, and any proof.
    ///
    /// Rows must arrive newest first. A proof error about this row's pages returns
    /// as `Err`, and the row's roots stay out of the bound. Then the next row
    /// compares against a root sealed later than it needs, which only misses.
    pub(crate) async fn scan_history_row(
        &self,
        scan: &mut HistorySealScan,
        meta: &CommitHistoryMeta,
    ) -> Result<(BTreeSet<u64>, Option<ResealEvidence>)> {
        let roots = [meta.active_root_page_id, meta.catalog_root_page_id];
        let mut reached = BTreeSet::new();
        let mut newest = None;
        for root_page_id in roots {
            let tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                root_page_id,
                meta.next_page_id,
                self.page_size,
            );
            let tree_newest = tree.walk_page_seals(&mut scan.ledger, &mut reached).await?;
            newest = SealedPage::newer(newest, tree_newest);
        }
        let later_roots = std::mem::replace(&mut scan.later_roots, roots);
        for (later_root, row_root) in later_roots.into_iter().zip(roots) {
            if later_root == 0 || later_root == row_root {
                continue;
            }
            let later_seal = self.later_root_seal(scan, later_root).await?;
            scan.bound = SealedPage::older(scan.bound, later_seal);
        }
        if scan.ledger.saw_foreign_seal() {
            scan.void.get_or_insert(SealOrderVoid::MixedPageSeals);
        }
        let resealed = match (scan.void, newest, scan.bound) {
            (None, Some(page), Some(later_root)) if page.counter >= later_root.counter => {
                Some(ResealEvidence { page, later_root })
            }
            _ => None,
        };
        Ok((reached, resealed))
    }

    /// A row's root is in the ledger, because that row walked first. Only a live
    /// root needs a read. A live root that cannot authenticate says nothing about
    /// a row. It voids the scan, so the caller never takes it as proof.
    async fn later_root_seal(
        &self,
        scan: &mut HistorySealScan,
        page_id: u64,
    ) -> Result<Option<SealedPage>> {
        if let Some(seal) = scan.ledger.own(page_id) {
            return Ok(Some(seal));
        }
        match self
            .pager
            .read_main_node_sealed(page_id, self.realm_id)
            .await
        {
            Ok(read) => Ok(scan.ledger.comparable(page_id, &read.stamp)),
            Err(error) if proves_unreadable_pages(&error) => {
                scan.void.get_or_insert(SealOrderVoid::UnreadableLiveRoot);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// The newest row newer than `pruned_through` that seal order proves stale.
    ///
    /// Changes nothing. A store that cannot show seal order returns `None`. A page
    /// that stops authenticating between the two walks counts as proof, as in the
    /// first walk. Any other error fails the rekey.
    pub(crate) async fn newest_resealed_history_row(
        &self,
        state: &WriterState,
        pruned_through: Option<u64>,
    ) -> Result<Option<u64>> {
        let mut scan = self.begin_history_seal_scan(state);
        if scan.void().is_some() {
            return Ok(None);
        }
        let history = self.open_history_index(state);
        let mut before: Option<Bytes> = None;
        loop {
            let batch = history
                .collect_rev_batch_before(before.as_deref(), HISTORY_ROW_BATCH)
                .await?;
            for (key, row) in &batch {
                let commit = history_row_commit(key)?;
                if pruned_through.is_some_and(|pruned| commit <= pruned) {
                    return Ok(None);
                }
                let walked = match decode_commit_meta(row) {
                    Ok(meta) => self.scan_history_row(&mut scan, &meta).await,
                    Err(error) => Err(error),
                };
                match walked {
                    Ok((_, Some(_))) => {
                        tracing::warn!(
                            commit,
                            "a rekey prunes a retained commit with a page sealed after it"
                        );
                        return Ok(Some(commit));
                    }
                    Ok((_, None)) => {
                        if scan.void().is_some() {
                            return Ok(None);
                        }
                    }
                    Err(error) if proves_unreadable_pages(&error) => return Ok(Some(commit)),
                    Err(error) => return Err(error),
                }
            }
            if batch.len() < HISTORY_ROW_BATCH {
                return Ok(None);
            }
            before = batch.last().map(|(key, _)| key.clone());
        }
    }

    /// The deep walk's read-only pass over every row. Changes nothing.
    ///
    /// Returns the stale rows newest first, the verdict, and the error that ended
    /// the scan early, if one did. Rows a handle must not keep skip the pass,
    /// because they are already gone under every policy.
    pub(crate) async fn report_stale_history_rows(
        &self,
        state: &WriterState,
    ) -> (
        Vec<StaleHistoryRow>,
        HistorySealVerdict,
        Option<PagedbError>,
    ) {
        let mut condemned = Vec::new();
        if state.commit_history_root_page_id == 0 || self.history_rows_gone(state) {
            return (condemned, HistorySealVerdict::NoRows, None);
        }
        let mut scan = self.begin_history_seal_scan(state);
        if let Some(void) = scan.void() {
            return (condemned, HistorySealVerdict::Inconclusive(void), None);
        }
        let error = self
            .collect_stale_rows(state, &mut scan, &mut condemned)
            .await;
        let verdict = match (scan.void(), &error) {
            (_, Err(_)) => HistorySealVerdict::Inconclusive(SealOrderVoid::ScanInterrupted),
            (Some(void), Ok(())) => HistorySealVerdict::Inconclusive(void),
            (None, Ok(())) => HistorySealVerdict::Compared,
        };
        (condemned, verdict, error.err())
    }

    async fn collect_stale_rows(
        &self,
        state: &WriterState,
        scan: &mut HistorySealScan,
        condemned: &mut Vec<StaleHistoryRow>,
    ) -> Result<()> {
        let history = self.open_history_index(state);
        let mut before: Option<Bytes> = None;
        loop {
            let batch = history
                .collect_rev_batch_before(before.as_deref(), HISTORY_ROW_BATCH)
                .await?;
            for (key, row) in &batch {
                let commit = history_row_commit(key)?;
                let walked = match decode_commit_meta(row) {
                    Ok(meta) => self.scan_history_row(scan, &meta).await,
                    Err(error) => Err(error),
                };
                let evidence = match walked {
                    Ok((_, Some(found))) => Some(StaleRowEvidence::SealedAfterLaterRoot {
                        page_id: found.page.page_id,
                        page_counter: found.page.counter,
                        later_root_page_id: found.later_root.page_id,
                        later_root_counter: found.later_root.counter,
                    }),
                    Ok((_, None)) => None,
                    Err(error) if proves_unreadable_pages(&error) => {
                        Some(StaleRowEvidence::UnreadablePages {
                            description: error.to_string(),
                        })
                    }
                    Err(error) => return Err(error),
                };
                if let Some(evidence) = evidence {
                    condemned.push(StaleHistoryRow {
                        commit: crate::CommitId(commit),
                        evidence,
                    });
                }
            }
            if batch.len() < HISTORY_ROW_BATCH {
                return Ok(());
            }
            before = batch.last().map(|(key, _)| key.clone());
        }
    }

    fn open_history_index(&self, state: &WriterState) -> BTree<V> {
        BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        )
    }
}
