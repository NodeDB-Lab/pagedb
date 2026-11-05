//! Carrying the Follower's commit-history tree across an incremental apply.
//!
//! An apply installs the producer's roots wholesale. The commit-history tree is
//! not the producer's. A follower inherits it from the full snapshot it was
//! restored from and keeps it. Nothing in the delta protocol describes it.
//! The producer cannot see it either. Its allocator recycles the ids that host
//! the tree into the target's own trees, and the delta ships those ids by number.
//!
//! Overwriting those ids is safe for the bytes, because the target image is
//! staged and swapped atomically. The header this apply publishes still names
//! the old history root. If the target has taken that page, the root points at
//! another node. Then `begin_read_at` fails and the reclamation floor cannot be
//! derived. A deep walk reports the tree unreadable.
//!
//! The tree moves out of the way instead. When the incoming delta claims any
//! page the tree occupies, the apply reads its rows from the intact base image.
//! It bulk-loads them onto fresh ids above the target's allocation cursor. No
//! delta record can name those ids, because the cursor bounds every record. The
//! pages it vacates that the target does not claim return to this handle's free
//! list. The caller does that. When the delta claims none of its pages, nothing
//! moves. Relocation costs pages, so it happens only when the alternative is a
//! broken root.
//!
//! The rows themselves name data and catalog pages the delta can overwrite. Such
//! a row and every older row leave the carried tree. Then `begin_read_at`
//! reports them gone and admits no reader over newer bytes. A cut always loads
//! the surviving rows onto fresh ids, the same way a relocation does.

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

/// What one apply asks of the commit-history carry.
pub(super) struct HistoryCarry<'a> {
    pub staged_image: &'a str,
    pub delta_page_ids: &'a BTreeSet<u64>,
    pub target_page_ids: &'a BTreeSet<u64>,
    pub history_version: u64,
    pub alloc_cursor: u64,
    /// The newest commit whose row leaves the tree, with every older row.
    pub pruned_through: Option<u64>,
}

impl<V: Vfs + Clone> Db<V> {
    /// Decide where this handle's commit-history tree lives in the staged image.
    ///
    /// Reads run against the live Pager, which still serves the untouched base
    /// image. A load past the dirty budget flushes into `staged_image`. The rest
    /// stays dirty for the caller to flush there with everything else this apply
    /// produces. No relocated page reaches the live file.
    ///
    /// The tree stays in place unless the delta claims one of its pages or a row
    /// leaves it. A cut that removes every row publishes an empty history.
    pub(super) async fn carry_commit_history(
        &self,
        state: &WriterState,
        carry: HistoryCarry<'_>,
    ) -> Result<CarriedHistory> {
        let HistoryCarry {
            staged_image,
            delta_page_ids,
            target_page_ids,
            history_version,
            alloc_cursor,
            pruned_through,
        } = carry;
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
        if pruned_through.is_none() && occupied.is_disjoint(delta_page_ids) {
            return Ok(unmoved);
        }

        // Keys are the commit id big-endian, so key order is commit order.
        let pruned_key = pruned_through.map(u64::to_be_bytes);
        // The staged record owns its key, so that is copied; the value carries
        // through by refcount.
        let rows: Vec<(Vec<u8>, Bytes)> = base_tree
            .collect_all()
            .await?
            .into_iter()
            .filter(|(key, _)| pruned_key.is_none_or(|pruned| &key[..] > pruned.as_slice()))
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
        let mut loader = relocated.bulk_loader_to(staged_image)?;
        for (key, value) in rows {
            loader.push(key, value).await?;
        }
        loader.finish().await?;

        // A vacated page the target reaches is the target's now — the delta
        // brought its new contents — so only the rest is this handle's to free.
        let released_page_ids: BTreeSet<u64> =
            occupied.difference(target_page_ids).copied().collect();

        // An empty tree has no root, and a root of zero carries version zero.
        let root_page_id = relocated.root_page_id();
        let root_version = if root_page_id == 0 {
            0
        } else {
            history_version
        };
        Ok(CarriedHistory {
            root_page_id,
            root_version,
            entry_count,
            next_page_id: relocated.next_page_id().max(alloc_cursor),
            released_page_ids,
        })
    }
}
