//! Write-path operations: insert, append, delete, and range delete.

use std::sync::Arc;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::node::NodeKind;
use crate::btree::overflow;
use crate::btree::split::split_leaf;

use super::core::BTree;

impl<V: Vfs> BTree<V> {
    /// Insert or overwrite a key-value pair.
    pub async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        // Build the leaf value — inline if small enough, overflow chain otherwise.
        let leaf_value = if value.len() > self.page_size / 4 {
            let realm = self.realm_id;
            let ps = self.page_size;
            let pager = Arc::clone(&self.pager);
            let root_id =
                overflow::write_chain(&pager, realm, value, ps, &mut || self.allocate_page())
                    .await?;
            LeafValue::Overflow {
                total_len: value.len() as u64,
                root_page_id: root_id,
            }
        } else {
            LeafValue::Inline(value.to_vec())
        };

        if self.root_page_id == 0 {
            let new_root = self.allocate_page();
            let mut leaf = Leaf::new();
            leaf.upsert(key, leaf_value);
            // Write directly to the pager so the empty-tree root is visible
            // to subsequent reads. Future puts on this leaf pull it through
            // the dirty cache on first touch (see `ensure_leaf_dirty`).
            self.write_leaf(new_root, &leaf).await?;
            self.root_page_id = new_root;
            // Any cached append path is now stale (root changed).
            self.append_cached_path = None;
            return Ok(());
        }

        // Descend to find the leaf page_id. Returns the path; we'll fetch the
        // leaf via the dirty-cache-aware helper below.
        let path = self.path_to_leaf_for_key(key).await?;
        // Regular `put` invalidates the append cache — caller may have
        // mutated keys that aren't in monotonic order vs the cache.
        self.append_cached_path = None;
        self.append_last_key = None;
        let _split = self.put_at_path(path, key, leaf_value).await?;
        Ok(())
    }

    /// Insert `(key, leaf_value)` using a pre-computed `path` from the root
    /// to the target leaf. Returns `true` if the operation triggered a leaf
    /// split (in which case `path` is now stale and the caller must
    /// discard any cached version of it).
    ///
    /// Callers MUST guarantee `path` is currently valid — i.e. all
    /// internal-node `page_id`s along it still point at the same children
    /// they did at descent time, and the terminal leaf at `path[-1]` still
    /// holds the records that would receive `key`. The hot path of
    /// `put_append` exploits this to skip a full `path_to_leaf_for_key`
    /// descent on monotonic-key workloads.
    pub(super) async fn put_at_path(
        &mut self,
        path: Vec<u64>,
        key: &[u8],
        leaf_value: LeafValue,
    ) -> Result<bool> {
        let leaf_page_id = *path.last().expect("non-empty path");

        // Two cases:
        // (1) leaf is in `fresh_leaves` — it was created by an earlier split
        //     during this txn. It's already on a fresh page id; mutate in
        //     place, no `CoW`.
        // (2) otherwise — pull through the dirty-leaf cache as usual.
        let leaf_is_fresh = self.fresh_leaves.contains_key(&leaf_page_id);
        if !leaf_is_fresh {
            self.ensure_leaf_dirty(leaf_page_id, &path).await?;
        }

        let leaf: &mut Leaf = if leaf_is_fresh {
            self.fresh_leaves
                .get_mut(&leaf_page_id)
                .expect("fresh_leaves contains key")
        } else {
            self.dirty_leaves
                .get_mut(&leaf_page_id)
                .expect("ensure_leaf_dirty populated")
        };

        let monotonic = leaf.records.last().is_some_and(|(k, _)| key > k.as_slice())
            && !leaf.records.iter().any(|(k, _)| k.as_slice() == key);

        let (_is_new, old_value) = leaf.upsert(key, leaf_value);
        let fits = leaf.fits(self.page_size);

        // Free old overflow chain if a record was replaced (refcount-aware).
        if let Some(LeafValue::Overflow {
            root_page_id: old_root,
            ..
        }) = old_value
        {
            let new_cow_page = self.allocate_page();
            match overflow::release(&self.pager, self.realm_id, old_root, new_cow_page).await? {
                overflow::ReleaseResult::Freed { freed_pages } => {
                    for pid in freed_pages {
                        self.free_page(pid);
                    }
                    self.free_page(new_cow_page);
                }
                overflow::ReleaseResult::Decremented {
                    new_root_page_id: _,
                } => {
                    self.free_page(old_root);
                }
            }
        }

        if fits {
            // Stay in the dirty cache. No allocate_page, no spine update,
            // no encode. The flush() pass batches all of that.
            return Ok(false);
        }

        // Split path: leaf overflowed. Pull it out of whichever cache it
        // lives in, split into two fresh pages, propagate the new separator
        // up the spine, and stash both halves in `fresh_leaves` for encoding
        // at flush time.
        let leaf = if leaf_is_fresh {
            self.fresh_leaves
                .remove(&leaf_page_id)
                .expect("fresh before split")
        } else {
            // The leaf was scheduled for freeing when it entered the dirty
            // cache; remove it from that list since the split path takes
            // over the free.
            if let Some(pos) = self.scheduled_frees.iter().position(|&p| p == leaf_page_id) {
                self.scheduled_frees.swap_remove(pos);
            }
            self.dirty_parent_paths.remove(&leaf_page_id);
            self.dirty_leaves
                .remove(&leaf_page_id)
                .expect("dirty before split")
        };
        let new_leaf_page = self.allocate_page();
        let (mut left, mut right, sep_key) = split_leaf(leaf, monotonic, self.page_size);
        let right_page = self.allocate_page();
        left.left_sibling = 0;
        left.right_sibling = 0;
        right.left_sibling = 0;
        right.right_sibling = 0;
        // Defer encode + pager write until flush. Both halves are pinned to
        // fresh page ids; no further CoW or spine fix-up is required.
        self.fresh_leaves.insert(new_leaf_page, left);
        self.fresh_leaves.insert(right_page, right);
        self.free_page(leaf_page_id);
        self.propagate_split_up(path, new_leaf_page, right_page, sep_key)
            .await?;
        Ok(true)
    }

    /// Append a key-value pair under the monotonic-key invariant. Subsequent
    /// monotonic calls skip the `path_to_leaf_for_key` descent by reusing
    /// the cached rightmost path; only splits and explicitly-invalidating
    /// operations (regular `put`/`delete`) force a re-descent.
    ///
    /// # Errors
    ///
    /// Returns [`PagedbError::AppendNotMonotonic`] if `key` is not strictly
    /// greater than the previously-appended key in this `BTree` session.
    /// Intended for op-logs, time-series indexes, FTS posting-list builds —
    /// any workload where the embedder can guarantee monotonic-key insert.
    pub async fn put_append(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        // Monotonic invariant: strictly greater than the last appended key.
        if let Some(last) = &self.append_last_key {
            if key <= last.as_slice() {
                return Err(PagedbError::AppendNotMonotonic);
            }
        }

        // Empty tree: delegate to the regular `put` path, which initializes
        // the root and writes the first leaf. After it returns, seed the
        // append cache with the new key.
        if self.root_page_id == 0 {
            self.put(key, value).await?;
            self.append_last_key = Some(key.to_vec());
            // The cached path needs a real descent on the next call.
            return Ok(());
        }

        // Build the leaf value (inline or overflow).
        let leaf_value = if value.len() > self.page_size / 4 {
            let realm = self.realm_id;
            let ps = self.page_size;
            let pager = Arc::clone(&self.pager);
            let root_id =
                overflow::write_chain(&pager, realm, value, ps, &mut || self.allocate_page())
                    .await?;
            LeafValue::Overflow {
                total_len: value.len() as u64,
                root_page_id: root_id,
            }
        } else {
            LeafValue::Inline(value.to_vec())
        };

        // Fast path: cached rightmost path is valid → skip descent.
        let path = if let Some(cached) = self.append_cached_path.take() {
            cached
        } else {
            self.path_to_rightmost_leaf().await?
        };
        let path_for_retry = path.clone();
        let split = self.put_at_path(path, key, leaf_value).await?;
        self.append_last_key = Some(key.to_vec());
        if split {
            // Split rewrote the rightmost leaf into two new leaves and
            // possibly CoW'd the spine. The cached path is stale.
            // Re-establish on next call via a fresh `path_to_rightmost_leaf`.
            self.append_cached_path = None;
        } else {
            self.append_cached_path = Some(path_for_retry);
        }
        Ok(())
    }

    /// Pull `page_id`'s leaf into [`Self::dirty_leaves`] if not already there.
    /// Decodes from the pager on first touch; subsequent calls are no-ops.
    /// On first touch also (a) schedules `page_id` for freeing and (b) records
    /// the leaf's spine path so flush can `CoW` only the affected internals.
    /// `path` ends at `page_id` (the leaf); the internals are `path[..len-1]`.
    async fn ensure_leaf_dirty(&mut self, page_id: u64, path: &[u64]) -> Result<()> {
        if self.dirty_leaves.contains_key(&page_id) {
            return Ok(());
        }
        let leaf = self.decode_leaf_from_pager(page_id).await?;
        self.dirty_leaves.insert(page_id, leaf);
        self.scheduled_frees.push(page_id);
        let parent_chain = if path.len() <= 1 {
            Vec::new()
        } else {
            path[..path.len() - 1].to_vec()
        };
        self.dirty_parent_paths.insert(page_id, parent_chain);
        Ok(())
    }

    /// Delete a key. Returns `true` if the key was present.
    pub async fn delete(&mut self, key: &[u8]) -> Result<bool> {
        // `delete` may have removed the previously-appended max, so the
        // monotonic invariant on `put_append` can no longer be enforced
        // against `append_last_key`. Reset the append state.
        self.append_cached_path = None;
        self.append_last_key = None;
        if self.root_page_id == 0 {
            return Ok(false);
        }
        let path = self.path_to_leaf_for_key(key).await?;
        let leaf_page_id = *path.last().expect("non-empty path");
        let leaf_is_fresh = self.fresh_leaves.contains_key(&leaf_page_id);
        if !leaf_is_fresh {
            self.ensure_leaf_dirty(leaf_page_id, &path).await?;
        }
        let removed = if leaf_is_fresh {
            self.fresh_leaves
                .get_mut(&leaf_page_id)
                .expect("fresh contains key")
                .remove(key)
        } else {
            self.dirty_leaves
                .get_mut(&leaf_page_id)
                .expect("dirty after ensure")
                .remove(key)
        };
        match removed {
            None => return Ok(false),
            Some(LeafValue::Overflow {
                root_page_id: old_root,
                ..
            }) => {
                let new_cow_page = self.allocate_page();
                match overflow::release(&self.pager, self.realm_id, old_root, new_cow_page).await? {
                    overflow::ReleaseResult::Freed { freed_pages } => {
                        for pid in freed_pages {
                            self.free_page(pid);
                        }
                        self.free_page(new_cow_page);
                    }
                    overflow::ReleaseResult::Decremented {
                        new_root_page_id: _,
                    } => {
                        self.free_page(old_root);
                    }
                }
            }
            Some(LeafValue::Inline(_)) => {}
        }
        // Leaf stays in dirty cache; flush() materializes it.
        Ok(true)
    }

    /// Batch insert of sorted `(key, value)` pairs. Sorted input is required;
    /// individual puts are issued per record.
    ///
    /// Per-leaf batching (amortising `CoW`) is a deferred performance
    /// optimisation; this implementation is correct for all inputs.
    pub async fn put_batch(&mut self, pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        for (k, v) in pairs {
            self.put(&k, &v).await?;
        }
        Ok(())
    }

    /// Batch delete of sorted keys.
    ///
    /// Per-leaf batching is a deferred performance optimisation; this
    /// implementation is correct for all inputs.
    pub async fn delete_batch(&mut self, keys: Vec<Vec<u8>>) -> Result<()> {
        for k in keys {
            self.delete(&k).await?;
        }
        Ok(())
    }

    /// Delete all records where `start <= key < end`. Returns the count of
    /// deleted records. Empty leaves are left in place (rebalancing is
    /// deferred).
    ///
    /// Implementation: collect the full set of matching keys via a forward
    /// scan, then delete each one individually. This avoids the multi-path
    /// `CoW` complexity of in-place range mutation.
    pub async fn delete_range(&mut self, start: &[u8], end: &[u8]) -> Result<u64> {
        if self.root_page_id == 0 {
            return Ok(0);
        }
        // Collect all keys in range (keys only, no values needed).
        let mut page_id = self.root_page_id;
        loop {
            if self.fresh_leaves.contains_key(&page_id) {
                break;
            }
            let kind = self.read_node_kind(page_id).await?;
            if kind == NodeKind::Leaf {
                break;
            }
            let internal = self.read_internal(page_id).await?;
            page_id = internal.child_for(start);
        }
        let mut keys_to_delete: Vec<Vec<u8>> = Vec::new();
        let mut next = page_id;
        'outer: while next != 0 {
            let leaf = self.read_leaf(next).await?;
            for (k, _) in &leaf.records {
                if k.as_slice() >= end {
                    break 'outer;
                }
                if k.as_slice() >= start {
                    keys_to_delete.push(k.clone());
                }
            }
            next = leaf.right_sibling;
        }
        let count = keys_to_delete.len() as u64;
        for key in keys_to_delete {
            self.delete(&key).await?;
        }
        Ok(count)
    }
}
