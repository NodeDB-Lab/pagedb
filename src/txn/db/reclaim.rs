//! Making an incremental apply's header describe a state `main.db` actually
//! contains: folding the reclaim set into the Follower's durable free list, and
//! backing the allocation cursor the apply publishes with real file extent.
//!
//! An apply installs the producer's roots wholesale. Every page those roots
//! stopped referencing — reachable from the base commit, absent from the
//! target — is dead the instant the new header is durable, and the only place
//! that can record it is this handle's own free-list chain, since the producer
//! neither owns nor can see it. Without this the pages are reachable from no
//! root and named by no free-list entry: space that never returns.
//!
//! The reclaim set is the *only* thing folded here, and deliberately so. Ids
//! below the published cursor that no root reaches are the producer's free
//! space: the follower replicates that page space but does not own it and never
//! allocates from it, so pulling those ids into follower-owned structures would
//! claim an authority this handle does not have. It would also be actively
//! harmful — chain pages join the published base set that an apply refuses to
//! overwrite, so a longer chain means more ids the producer's next delta
//! collides with, trading a phantom leak for real replication failures.
//!
//! The rewrite mirrors the one a normal commit performs: entries carry the
//! commit that freed them, the chain is hosted only on pages already free and
//! below the reclamation floor, and the new head reaches disk with the same
//! header swap that installs the roots. Nothing here is reachable from the
//! still-durable old header, so an apply interrupted before that swap leaves
//! the previous chain intact and the retry redoes the fold from scratch.

use std::collections::BTreeSet;

use crate::Result;
use crate::errors::PagedbError;
use crate::pager::freelist::{self, CHAIN_METADATA_CID};
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

use super::core::{Db, WriterState};

/// A rewritten free-list chain that is staged in the Pager but not yet durable:
/// the header swap that carries `free_list_root_page_id` is what commits it.
pub(super) struct StagedFreeList {
    pub free_list_root_page_id: u64,
    pub next_page_id: u64,
}

impl<V: Vfs + Clone> Db<V> {
    /// Rebuild this handle's free-list chain for an incremental apply.
    ///
    /// `reclaimed` is the set of base-reachable pages the target no longer
    /// reaches, `target_page_ids` the target's reachable set, and
    /// `freeing_commit_id` the commit the apply is installing. Chain pages are
    /// written through the Pager; the caller flushes and commits the header.
    pub(super) async fn stage_reclaimed_free_list(
        &self,
        state: &WriterState,
        reclaimed: &BTreeSet<u64>,
        target_page_ids: &BTreeSet<u64>,
        freeing_commit_id: u64,
        alloc_cursor: u64,
    ) -> Result<StagedFreeList> {
        // Deliberately the whole chain, not the write path's bounded window.
        // The fold has to answer a question about the *complete* entry set —
        // whether the target's roots reach any page this handle records as free
        // — and drop every such entry. An entry left unexamined in an unscanned
        // tail is a page the follower's free list hands out while its own roots
        // still point at it, which is the double-free this check exists to
        // prevent. Residency is the price; an apply is not the per-commit hot
        // path, and it already materialises the base and target page sets.
        let (existing, old_chain_pages) =
            freelist::read_chain(&self.pager, self.realm_id, state.free_list_root_page_id).await?;

        // A page the base recorded as free that the target now reaches was
        // legitimately reallocated by the producer: it is live again and must
        // leave the chain, or the follower's free list hands out a page its own
        // roots point at.
        let reallocated = existing
            .iter()
            .any(|(_, page_id)| target_page_ids.contains(page_id));
        if reclaimed.is_empty() && !reallocated {
            return Ok(StagedFreeList {
                free_list_root_page_id: state.free_list_root_page_id,
                next_page_id: alloc_cursor,
            });
        }

        let mut entries: Vec<(u64, u64)> =
            Vec::with_capacity(existing.len() + reclaimed.len() + old_chain_pages.len());
        for (freed_at, page_id) in existing {
            if target_page_ids.contains(&page_id) {
                continue;
            }
            // A reclaimed page was reader-visible at the base commit, so it
            // cannot also have been free there. If it is, this handle's state
            // is already inconsistent, and folding it in would put one page id
            // in the chain twice — a double-free, which is worse than the leak
            // this fold exists to close.
            if reclaimed.contains(&page_id) {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::CatalogRowInvalid {
                        field: "free-list entry names a page the base commit still reaches",
                    },
                ));
            }
            entries.push((freed_at, page_id));
        }

        // Hosts for the rewritten chain: pages that are already free *and*
        // below the reclamation floor, so no pinned reader and no retained
        // history root can still reach them, and the still-durable header does
        // not reference them either. Reclaimed pages never qualify — they are
        // live under that header until the swap.
        let floor = self.reclamation_floor(state).await?;
        let host_candidates: Vec<u64> = entries
            .iter()
            .filter(|(freed_at, _)| *freed_at < floor)
            .map(|(_, page_id)| *page_id)
            .collect();

        // Tag the reclaimed pages with the commit this apply installs so the
        // floor keeps them out of circulation for as long as a reader pinned at
        // the pre-apply state can still reach them.
        entries.extend(
            reclaimed
                .iter()
                .map(|&page_id| (freeing_commit_id, page_id)),
        );
        entries.extend(
            old_chain_pages
                .iter()
                .map(|&page_id| (CHAIN_METADATA_CID, page_id)),
        );

        let (free_list_root_page_id, next_page_id) = freelist::rewrite_chain(
            &self.pager,
            self.realm_id,
            self.page_size,
            entries,
            host_candidates,
            alloc_cursor,
            // The whole chain was read, so there is no retained tail to splice.
            0,
        )
        .await?;
        Ok(StagedFreeList {
            free_list_root_page_id,
            next_page_id,
        })
    }

    /// Grow `main.db` so every page id below `next_page_id` is readable.
    ///
    /// The invariant: a published allocation cursor must never describe pages
    /// the file does not contain. An apply adopts the producer's cursor, but it
    /// only ever receives the pages the target's roots reach — the producer's
    /// own free pages and free-list chain sit below that cursor and are never
    /// shipped, so the file can legitimately end short of it. Every reader that
    /// sweeps the id space (`fsck`, the deep walk, a promoted writer's
    /// recovery) then meets an id inside the allocator's range with nothing
    /// behind it, which is indistinguishable from a truncated store.
    ///
    /// Growing is unconditional and shrinking never happens: this must not undo
    /// a delta write or a chain page that landed past the cursor. The zero
    /// pages it materializes carry no AEAD tag and so can never be
    /// authenticated. That is not damage and not a leak here: they are the
    /// producer's free space, which this handle replicates without owning, so
    /// the deep walk deliberately does not hold a replicating handle to account
    /// for them.
    pub(super) async fn ensure_main_db_covers_cursor(&self, next_page_id: u64) -> Result<()> {
        let page_size = u64::try_from(self.page_size)
            .map_err(|_| PagedbError::arithmetic_overflow("page size"))?;
        let required = next_page_id
            .checked_mul(page_size)
            .ok_or_else(|| PagedbError::arithmetic_overflow("main.db extent"))?;
        let mut file = self
            .vfs
            .open(&self.main_db_path, OpenMode::CreateOrOpen)
            .await?;
        if file.len().await? >= required {
            return Ok(());
        }
        file.set_len(required).await?;
        file.sync().await
    }

    /// Commit id below which free-list entries are recyclable: the older of the
    /// oldest live-reader pin and the oldest retained commit-history root.
    /// Same derivation the write path uses at `begin`.
    async fn reclamation_floor(&self, state: &WriterState) -> Result<u64> {
        let min_reader = {
            let readers = self.tracked_readers.lock();
            readers.iter().map(|reader| reader.commit_id.0).min()
        };
        let history_floor = self
            .oldest_retained_history_commit(state.commit_history_root_page_id, state.next_page_id)
            .await?;
        Ok(min_reader
            .unwrap_or(u64::MAX)
            .min(history_floor.map_or(u64::MAX, |commit| commit.saturating_add(1))))
    }
}
