//! Settle retained commit history before a rekey walk can fail on it.
//!
//! A rekey re-seals every page each retained row reaches. A row with an
//! unreadable page fails that walk. The walk runs after the intent is durable,
//! and a resume runs it again on every open. One stale row then makes the store
//! unopenable.
//!
//! So a rekey first runs the same walk read-only. It uses the map the rewriting
//! walk uses, because a plain page set accepts a page reached under a second
//! role and the rewriting walk then reports that page as aliased.
//!
//! Rows run newest to oldest. The first row with proof about its pages leaves
//! with every older row, so the oldest retained commit stays monotonic. Only
//! proof about page bytes prunes. A transient error fails the operation and
//! leaves every row in place.
//!
//! A row can also authenticate and still name newer bytes. Seal order shows this
//! only until the rewrite below destroys it, so the same pass compares it first.
//! See the `history_seals` module for the proof and what voids it.
//!
//! The read path picks each page's key from the epoch in that page's envelope.
//! A resume therefore reads a mix of source and target pages with no extra work.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

use bytes::Bytes;

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{RekeyIntent, RekeyStage};
use crate::crypto::{CipherId, DerivedKey};
use crate::pager::PageKind;
use crate::vfs::Vfs;

use super::super::catalog::history_policy::{ALL_HISTORY_ROWS, proves_unreadable_pages};
use super::super::core::{Db, WriterState, decode_commit_meta};
use super::super::history_carry::HistoryCarry;
use super::main::{HISTORY_ROOT_BATCH, RekeyCatalogCommit};

impl<V: Vfs + Clone> Db<V> {
    /// The newest row this rekey must prune before it writes, or `None`.
    ///
    /// Changes nothing. An unreadable live page returns its error, because no
    /// prune repairs it. Refusing here leaves no intent behind.
    pub(super) async fn history_rows_rekey_prunes(
        &self,
        state: &WriterState,
    ) -> Result<Option<u64>> {
        let mut walked = BTreeMap::new();
        for root_page_id in [state.root_page_id, state.catalog_root_page_id] {
            BTree::open(
                self.pager.clone(),
                self.realm_id,
                root_page_id,
                state.next_page_id,
                self.page_size,
            )
            .verify_walk_unique(&mut walked)
            .await?;
        }
        if state.commit_history_root_page_id == 0 {
            return Ok(None);
        }
        if self.history_rows_gone(state) {
            return Ok(Some(ALL_HISTORY_ROWS));
        }
        let unreadable = self.newest_unreadable_history_row(state, walked).await?;
        if unreadable == Some(ALL_HISTORY_ROWS) {
            return Ok(unreadable);
        }
        // A rekey reseals in walk order, so this is the last chance to read seal
        // order. A store that cannot show it answers `None`.
        let resealed = self.newest_resealed_history_row(state, unreadable).await?;
        Ok(unreadable.max(resealed))
    }

    async fn newest_unreadable_history_row(
        &self,
        state: &WriterState,
        mut walked: BTreeMap<u64, PageKind>,
    ) -> Result<Option<u64>> {
        let history = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        // An index that cannot authenticate names no row a reader can trust.
        match history.verify_walk_unique(&mut walked).await {
            Ok(()) => {}
            Err(error) if proves_unreadable_pages(&error) => {
                tracing::warn!(%error, "history index unreadable; a rekey removes every row");
                return Ok(Some(ALL_HISTORY_ROWS));
            }
            Err(error) => return Err(error),
        }
        let mut before: Option<Bytes> = None;
        loop {
            let batch = history
                .collect_rev_batch_before(before.as_deref(), HISTORY_ROOT_BATCH)
                .await?;
            for (key, row) in &batch {
                // A malformed key orders nothing, so no prefix of the rows can
                // be trusted to stop at the right place.
                let Ok(commit) = <[u8; 8]>::try_from(&key[..]) else {
                    tracing::warn!("malformed history key; a rekey removes every row");
                    return Ok(Some(ALL_HISTORY_ROWS));
                };
                let commit = u64::from_be_bytes(commit);
                match self.verify_history_row_pages(row, &mut walked).await {
                    Ok(()) => {}
                    Err(error) if proves_unreadable_pages(&error) => {
                        tracing::warn!(
                            commit,
                            %error,
                            "a rekey prunes a retained commit whose pages cannot authenticate"
                        );
                        return Ok(Some(commit));
                    }
                    Err(error) => return Err(error),
                }
            }
            if batch.len() < HISTORY_ROOT_BATCH {
                return Ok(None);
            }
            before = batch.last().map(|(key, _)| key.clone());
        }
    }

    /// The row's free-list root stays unread. It is superseded writer metadata
    /// that no reader and no rekey walk follows.
    async fn verify_history_row_pages(
        &self,
        row: &[u8],
        walked: &mut BTreeMap<u64, PageKind>,
    ) -> Result<()> {
        let meta = decode_commit_meta(row)?;
        for root_page_id in [meta.active_root_page_id, meta.catalog_root_page_id] {
            BTree::open(
                self.pager.clone(),
                self.realm_id,
                root_page_id,
                meta.next_page_id,
                self.page_size,
            )
            .verify_walk_unique(walked)
            .await?;
        }
        Ok(())
    }

    /// Durably remove the row at `pruned_through` and every older row.
    ///
    /// The surviving rows load onto fresh ids and the old tree joins the free
    /// list, so a crash before the header leaves the old rows whole. The caller
    /// names the header identity the store holds at this stage. The catalog root
    /// does not move, so a source-readable intent stays source-readable.
    pub(super) async fn prune_history_rows_locked(
        &self,
        state: &mut WriterState,
        pruned_through: u64,
        header_epoch: u64,
        header_hk: &DerivedKey,
    ) -> Result<()> {
        let nothing = BTreeSet::new();
        let carried = self
            .carry_commit_history(
                state,
                HistoryCarry {
                    staged_image: None,
                    delta_page_ids: &nothing,
                    target_page_ids: &nothing,
                    history_version: state.latest_commit_id,
                    alloc_cursor: state.next_page_id,
                    pruned_through: Some(pruned_through),
                },
            )
            .await?;
        self.pager.flush_main(self.realm_id).await?;
        let freed_pages: Vec<u64> = carried.released_page_ids.iter().copied().collect();
        state.commit_history_root_page_id = carried.root_page_id;
        state.commit_history_root_version = carried.root_version;
        state.commit_history_count = carried.entry_count;
        let catalog_root_page_id = state.catalog_root_page_id;
        self.commit_rekey_catalog_root(
            state,
            RekeyCatalogCommit {
                catalog_root_page_id,
                next_page_id: carried.next_page_id,
                freed_pages: &freed_pages,
                effects: &[],
            },
            header_epoch,
            header_hk,
        )
        .await
        .map(drop)
    }

    /// Settle history for an intent an earlier open or an older release wrote.
    ///
    /// Only these two stages still have a pass that a stale row can fail. The
    /// first holds the row walk. The second holds the free-list pass.
    ///
    /// Both intent keys must be installed first. `MissingPersistedKey` proves
    /// a page's envelope is wrong only while no key the store can use is absent.
    /// `admit_rekey_recovery` installs them or refuses the open, and a missing
    /// lease here fails with no prune.
    pub(super) async fn settle_history_for_resume(
        &self,
        state: &mut WriterState,
        intent: &RekeyIntent,
    ) -> Result<()> {
        self.pager.mk_for(
            intent.source_mk_epoch,
            CipherId::from_byte(intent.source_cipher_id)?,
        )?;
        self.pager.mk_for(
            intent.target_mk_epoch,
            CipherId::from_byte(intent.target_cipher_id)?,
        )?;
        if !matches!(
            intent.stage,
            RekeyStage::Intent | RekeyStage::HeaderTargetPublished
        ) {
            return Ok(());
        }
        let Some(pruned_through) = self.history_rows_rekey_prunes(state).await? else {
            return Ok(());
        };
        let header_epoch = self.mk_epoch.load(Ordering::SeqCst);
        let header_hk = self.hk.read().clone();
        self.prune_history_rows_locked(state, pruned_through, header_epoch, &header_hk)
            .await
    }
}
