//! What a handle does with the commit-history rows a store holds.
//!
//! `RetainPolicy::Disabled` means no rows. A handle under it serves the latest
//! commit only, and its first commit removes the tree.
//!
//! A header with retention tag 3 and a non-zero history root is proof about the
//! past. A release that kept the old root under `Disabled` wrote it. Its commits
//! recycled pages those rows name, so the rows are gone under every policy.
//! This build never writes that pair over rows it maintains. Its commit writes
//! root 0 with tag 3, and every other header repeats the last tag.
//!
//! A `Disabled` handle still honours rows it has not removed yet. Its commit
//! writes pages before the header lands. A crash there leaves the old header
//! naming the old rows, so those commits must not recycle what the rows reach.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use crate::Result;
use crate::btree::BTree;
use crate::errors::PagedbError;
use crate::options::RetainPolicy;
use crate::txn::db::core::{Db, WriterState};
use crate::txn::db::pending::PendingWriterState;
use crate::vfs::Vfs;

/// The header retention tag of `RetainPolicy::Disabled`.
pub(crate) const RETAIN_POLICY_TAG_DISABLED: u8 = 3;

/// A `pruned_through` value that removes every row. No commit reaches this id.
pub(crate) const ALL_HISTORY_ROWS: u64 = u64::MAX;

/// Whether this header pair proves its rows went unmaintained.
pub(crate) fn history_rows_abandoned(retain_tag: u8, history_root_page_id: u64) -> bool {
    retain_tag == RETAIN_POLICY_TAG_DISABLED && history_root_page_id != 0
}

/// Whether an error from a main-page read proves the page cannot serve that read.
///
/// This is the one classifier for a durable decision: pruning a row, dropping a
/// history tree, or blanking a free page. Each accepted variant has one source
/// on the page read path:
///
/// - `ChecksumFailure`, `IllegalPageKind`, `Corruption`: the page's kind or tag
///   fails, or its cipher byte names no cipher. `Pager::read_page` reports that
///   byte as `Corruption`.
/// - `MissingPersistedKey`: `EpochKeyring::lease`, from the epoch and cipher in
///   the page's envelope. No page of a settled store carries another epoch, and
///   a wrong KEK fails the header MAC before any page read. A resume leases both
///   intent keys first, so the page's envelope is the only cause left.
/// - `Io` of kind `UnexpectedEof`: only `checked_read_progress`, when `read_at`
///   returns zero. Zero means end of file, no backend raises this kind itself,
///   and the writer lock excludes a concurrent truncate.
///
/// `Unsupported` stays out. A VFS raises it too, such as an OPFS worker's
/// mismatched reply, and that says nothing about the page. Every other `Io` kind
/// and a cache fault also say nothing about it, so they fail the operation.
pub(crate) fn proves_unreadable_pages(error: &PagedbError) -> bool {
    match error {
        PagedbError::ChecksumFailure
        | PagedbError::IllegalPageKind
        | PagedbError::Corruption(_)
        | PagedbError::MissingPersistedKey { .. } => true,
        PagedbError::Io(io_error) => io_error.kind() == std::io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

impl<V: Vfs + Clone> Db<V> {
    pub(crate) fn history_disabled(&self) -> bool {
        matches!(self.options.commit_history_retain, RetainPolicy::Disabled)
    }

    /// Whether this handle owes the store the removal of its rows.
    pub(crate) fn history_rows_gone(&self, state: &WriterState) -> bool {
        self.history_disabled()
            || history_rows_abandoned(
                state.commit_retain_policy_tag,
                state.commit_history_root_page_id,
            )
    }

    /// The bound retained rows put on free-page reuse: an entry tagged below it
    /// is out of every row's reach. `None` means rows set no bound.
    ///
    /// A commit tags a page it frees with its own id, so only older rows reach
    /// that page. The bound is `oldest + 1` on such a store.
    ///
    /// A rekey by an earlier release tagged superseded catalog pages with the
    /// latest commit, so that commit's own row still reaches them. Any store with
    /// a rekey behind it has an epoch above zero and can hold such a tag. The
    /// bound is `oldest` there.
    pub(crate) async fn history_reclamation_bound(
        &self,
        state: &WriterState,
    ) -> Result<Option<u64>> {
        if history_rows_abandoned(
            state.commit_retain_policy_tag,
            state.commit_history_root_page_id,
        ) {
            return Ok(None);
        }
        let oldest = match self
            .oldest_retained_history_commit(state.commit_history_root_page_id, state.next_page_id)
            .await
        {
            Ok(oldest) => oldest,
            // This handle has to commit, because that commit removes the tree.
            // Zero admits no entry, so the commit reuses nothing while it does.
            Err(error) if self.history_disabled() && proves_unreadable_pages(&error) => {
                tracing::warn!(%error, "history tree unreadable under RetainPolicy::Disabled");
                return Ok(Some(0));
            }
            Err(error) => return Err(error),
        };
        let rekeyed = self.mk_epoch.load(Ordering::SeqCst) > 0;
        Ok(oldest.map(|commit| {
            if rekeyed {
                commit
            } else {
                commit.saturating_add(1)
            }
        }))
    }

    /// The pages a dropped history tree occupies.
    ///
    /// A tree that cannot authenticate returns none. A partial walk can name a
    /// page the tree no longer owns, and freeing that page gives it two owners.
    /// The pages stay leaked until a full compaction rebuilds the file.
    pub(crate) async fn droppable_history_pages(
        &self,
        root_page_id: u64,
        next_page_id: u64,
    ) -> Result<BTreeSet<u64>> {
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            root_page_id,
            next_page_id,
            self.page_size,
        );
        let mut pages = BTreeSet::new();
        match tree.collect_all_page_ids(&mut pages).await {
            Ok(()) => Ok(pages),
            Err(error) if proves_unreadable_pages(&error) => {
                tracing::warn!(
                    history_root = root_page_id,
                    %error,
                    "history tree unreadable; its pages stay leaked until a compaction"
                );
                Ok(BTreeSet::new())
            }
            Err(error) => Err(error),
        }
    }

    /// Remove the whole history tree from a candidate commit. Returns the pages
    /// the commit must add to the free list.
    ///
    /// The pages stay intact until the header naming root 0 is durable. They
    /// reach an allocator only through a later commit's free-list window.
    pub(crate) async fn drop_commit_history(
        &self,
        state: &mut PendingWriterState,
    ) -> Result<Vec<u64>> {
        let root_page_id = state.commit_history_root_page_id;
        if root_page_id == 0 {
            return Ok(Vec::new());
        }
        let pages = self
            .droppable_history_pages(root_page_id, state.next_page_id)
            .await?;
        state.commit_history_root_page_id = 0;
        state.commit_history_root_version = 0;
        state.commit_history_count = Some(0);
        Ok(pages.into_iter().collect())
    }
}
