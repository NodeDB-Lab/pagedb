//! Carrying the Follower's commit-history tree across an incremental apply.
//!
//! An apply installs the producer's roots wholesale, but the commit-history
//! tree is not the producer's — a follower inherits it from the full snapshot it
//! was restored from and then keeps it, because nothing in the delta protocol
//! describes it. The producer cannot see it either, so its allocator will
//! happily recycle the ids that host it into the target's own trees, and the
//! delta then ships those ids by number.
//!
//! Overwriting them is safe now that the target image is staged and swapped
//! atomically — but only for the *bytes*. The header this apply publishes still
//! names the old history root, and if the target has taken that page, the root
//! points at somebody else's node: `begin_read_at` fails, the reclamation floor
//! cannot be derived, and a deep walk reports the tree unreadable.
//!
//! So the tree is moved out of the way instead of being defended. When the
//! incoming delta claims any page it occupies, its rows are read from the still
//! intact base image and bulk-loaded onto fresh ids above the target's
//! allocation cursor — ids no delta record can name, since every record is
//! bounded by that cursor. The pages it vacates that the target does not claim
//! are returned to this handle's free list by the caller. When the delta claims
//! none of its pages, nothing moves: relocation costs pages, so it happens only
//! when the alternative is a broken root.

use std::collections::BTreeSet;

use bytes::Bytes;

use crate::Result;
use crate::btree::BTree;
use crate::vfs::Vfs;

use super::core::{Db, WriterState};

/// Where the commit-history tree lives once the apply's target image is built.
pub(super) struct CarriedHistory {
    pub root_page_id: u64,
    pub root_version: u64,
    pub entry_count: Option<u64>,
    /// Allocation cursor after any relocation. Never below the caller's input.
    pub next_page_id: u64,
    /// Pages the previous copy occupied and the target does not claim, so the
    /// caller can record them as free rather than strand them.
    pub released_page_ids: BTreeSet<u64>,
}

impl<V: Vfs + Clone> Db<V> {
    /// Decide where this handle's commit-history tree lives in the staged image.
    ///
    /// Reads run against the live Pager, which still serves the untouched base
    /// image; any pages written land in the Pager's dirty set for the caller to
    /// flush into the staged image with everything else this apply produces.
    pub(super) async fn carry_commit_history(
        &self,
        state: &WriterState,
        delta_page_ids: &BTreeSet<u64>,
        target_page_ids: &BTreeSet<u64>,
        history_version: u64,
        alloc_cursor: u64,
    ) -> Result<CarriedHistory> {
        let unmoved = CarriedHistory {
            root_page_id: state.commit_history_root_page_id,
            root_version: state.commit_history_root_version,
            entry_count: state.commit_history_count,
            next_page_id: alloc_cursor,
            released_page_ids: BTreeSet::new(),
        };
        if state.commit_history_root_page_id == 0 {
            return Ok(unmoved);
        }

        let base_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let mut occupied = BTreeSet::new();
        base_tree.collect_all_page_ids(&mut occupied).await?;
        if occupied.is_disjoint(delta_page_ids) {
            return Ok(unmoved);
        }

        // The staged record owns its key, so that is copied; the value carries
        // through by refcount.
        let rows: Vec<(Vec<u8>, Bytes)> = base_tree
            .collect_all()
            .await?
            .into_iter()
            .map(|(key, value)| (key.to_vec(), value))
            .collect();
        let entry_count = u64::try_from(rows.len()).ok();
        let mut relocated = BTree::open(
            self.pager.clone(),
            self.realm_id,
            0,
            alloc_cursor,
            self.page_size,
        );
        relocated.bulk_load(rows).await?;

        // A vacated page the target reaches is the target's now — the delta
        // brought its new contents — so only the rest is this handle's to free.
        let released_page_ids: BTreeSet<u64> =
            occupied.difference(target_page_ids).copied().collect();

        Ok(CarriedHistory {
            root_page_id: relocated.root_page_id(),
            root_version: history_version,
            entry_count,
            next_page_id: relocated.next_page_id().max(alloc_cursor),
            released_page_ids,
        })
    }
}
