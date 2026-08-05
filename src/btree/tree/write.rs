//! Write-path operations: insert, append, delete, and range delete.

use std::sync::Arc;

use bytes::Bytes;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::overflow;
use crate::btree::split::split_leaf;

use super::core::{BTree, SeenPageIds};

impl<V: Vfs> BTree<V> {
    fn invalidate_append_state(&mut self) {
        self.append_cached_path = None;
        self.append_last_key = None;
    }

    fn cached_leaf_mut(&mut self, page_id: u64, leaf_is_fresh: bool) -> &mut Leaf {
        if leaf_is_fresh {
            self.fresh_leaves
                .get_mut(&page_id)
                .expect("fresh_leaves contains key")
        } else {
            self.dirty_leaves
                .get_mut(&page_id)
                .expect("ensure_leaf_dirty populated")
        }
    }

    fn apply_release_result(
        &mut self,
        old_root: u64,
        unused_cow_page: u64,
        release_result: overflow::ReleaseResult,
    ) {
        match release_result {
            overflow::ReleaseResult::Freed { freed_pages } => {
                for page_id in freed_pages {
                    self.free_page(page_id);
                }
                self.free_page(unused_cow_page);
            }
            overflow::ReleaseResult::Decremented => self.free_page(old_root),
        }
    }

    /// Return the pages of a chain that was written for a value the caller
    /// never got to commit.
    ///
    /// Best-effort by design: this runs on an error path, and a failure here
    /// must not replace the error the caller actually needs to see. It is
    /// logged rather than swallowed, because the cost of giving up is a page
    /// leak that nothing else will notice.
    async fn discard_uncommitted_value(&mut self, value: Option<LeafValue>) {
        let Some(LeafValue::Overflow { root_page_id, .. }) = value else {
            return;
        };
        match overflow::collect_chain(&self.pager, self.realm_id, root_page_id).await {
            Ok(page_ids) => {
                for page_id in page_ids {
                    self.free_page(page_id);
                }
            }
            Err(error) => tracing::warn!(
                root_page_id,
                error = %error,
                "could not reclaim the overflow chain of an uncommitted value; its pages are leaked"
            ),
        }
    }

    async fn max_key_at_path(&self, path: &[u64]) -> Result<Option<Vec<u8>>> {
        let leaf_page_id = *path.last().expect("non-empty path");
        if let Some(leaf) = self.fresh_leaves.get(&leaf_page_id) {
            return Ok(leaf.records.last().map(|(key, _)| key.clone()));
        }
        if let Some(leaf) = self.dirty_leaves.get(&leaf_page_id) {
            return Ok(leaf.records.last().map(|(key, _)| key.clone()));
        }
        Ok(self
            .decode_leaf_from_pager(leaf_page_id)
            .await?
            .records
            .last()
            .map(|(key, _)| key.clone()))
    }

    async fn leaf_value_for(&mut self, value: &[u8]) -> Result<LeafValue> {
        if value.len() > overflow::inline_value_threshold(self.page_size) {
            let realm = self.realm_id;
            let page_size = self.page_size;
            let pager = Arc::clone(&self.pager);
            let root_page_id = overflow::write_chain(
                &pager,
                realm,
                value,
                page_size,
                &mut || self.allocate_page(),
                overflow::OverflowFlushTarget::Disabled,
            )
            .await?;
            Ok(LeafValue::Overflow {
                total_len: value.len() as u64,
                root_page_id,
            })
        } else {
            Ok(LeafValue::Inline(Bytes::copy_from_slice(value)))
        }
    }

    /// Insert or overwrite a key-value pair.
    pub async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.invalidate_append_state();
        self.validate_insert_record_fits(key, value)?;
        let leaf_value = self.leaf_value_for(value).await?;

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

        let page_size = self.page_size;
        let leaf = self.cached_leaf_mut(leaf_page_id, leaf_is_fresh);

        let monotonic = leaf.records.last().is_some_and(|(k, _)| key > k.as_slice())
            && !leaf.records.iter().any(|(k, _)| k.as_slice() == key);

        let (_is_new, old_value) = leaf.upsert(key, leaf_value);
        let fits = leaf.fits(page_size);

        // Free old overflow chain if a record was replaced (refcount-aware).
        if let Some(
            old_value @ LeafValue::Overflow {
                root_page_id: old_root,
                ..
            },
        ) = old_value
        {
            let new_cow_page = self.allocate_page();
            match overflow::release(&self.pager, self.realm_id, old_root, new_cow_page).await {
                Ok(release_result) => {
                    self.apply_release_result(old_root, new_cow_page, release_result);
                }
                Err(error) => {
                    self.free_page(new_cow_page);
                    let attempted_value = self
                        .cached_leaf_mut(leaf_page_id, leaf_is_fresh)
                        .upsert(key, old_value)
                        .1;
                    self.discard_uncommitted_value(attempted_value).await;
                    return Err(error);
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
    /// greater than the previously-appended key in this `BTree` session, or —
    /// on the first append of a session, when there is no such key yet — not
    /// strictly greater than the largest key already in the tree. Both are the
    /// same invariant: the cached rightmost path is only meaningful while every
    /// append lands to the right of everything before it.
    /// Intended for op-logs, time-series indexes, FTS posting-list builds —
    /// any workload where the embedder can guarantee monotonic-key insert.
    pub async fn put_append(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        // Monotonic invariant: strictly greater than the last appended key.
        if let Some(last) = &self.append_last_key {
            if key <= last.as_slice() {
                return Err(PagedbError::AppendNotMonotonic);
            }
        }
        self.validate_insert_record_fits(key, value)?;

        // Initialize directly: regular put invalidates append state by design.
        if self.root_page_id == 0 {
            let leaf_value = self.leaf_value_for(value).await?;
            let new_root = self.allocate_page();
            let mut leaf = Leaf::new();
            leaf.upsert(key, leaf_value);
            self.write_leaf(new_root, &leaf).await?;
            self.root_page_id = new_root;
            self.append_last_key = Some(key.to_vec());
            self.append_cached_path = Some(vec![new_root]);
            return Ok(());
        }

        // Fast path: cached rightmost path is valid → skip descent.
        let path = match &self.append_cached_path {
            Some(cached) => cached.clone(),
            None => self.path_to_rightmost_leaf().await?,
        };
        // Checked before the cached path is consumed: a rejected append must
        // leave the session exactly as it found it, cache included.
        if self.append_last_key.is_none()
            && self
                .max_key_at_path(&path)
                .await?
                .is_some_and(|max_key| key <= max_key.as_slice())
        {
            return Err(PagedbError::AppendNotMonotonic);
        }
        self.append_cached_path = None;
        let leaf_value = self.leaf_value_for(value).await?;
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
        self.invalidate_append_state();
        if self.root_page_id == 0 {
            return Ok(false);
        }
        let path = self.path_to_leaf_for_key(key).await?;
        let leaf_page_id = *path.last().expect("non-empty path");
        let leaf_is_fresh = self.fresh_leaves.contains_key(&leaf_page_id);
        if !leaf_is_fresh {
            self.ensure_leaf_dirty(leaf_page_id, &path).await?;
        }
        let removed = self
            .cached_leaf_mut(leaf_page_id, leaf_is_fresh)
            .remove(key);
        match removed {
            None => return Ok(false),
            Some(
                old_value @ LeafValue::Overflow {
                    root_page_id: old_root,
                    ..
                },
            ) => {
                let new_cow_page = self.allocate_page();
                match overflow::release(&self.pager, self.realm_id, old_root, new_cow_page).await {
                    Ok(release_result) => {
                        self.apply_release_result(old_root, new_cow_page, release_result);
                    }
                    Err(error) => {
                        self.free_page(new_cow_page);
                        self.cached_leaf_mut(leaf_page_id, leaf_is_fresh)
                            .upsert(key, old_value);
                        return Err(error);
                    }
                }
            }
            Some(LeafValue::Inline(_)) => {}
        }
        // Leaf stays in dirty cache; flush() materializes it.
        Ok(true)
    }

    /// Batch insert of sorted `(key, value)` pairs.
    ///
    /// Reuses the target leaf path and its exclusive upper bound while
    /// consecutive keys remain in the same leaf. A split invalidates the
    /// cached path; the next key descends through the updated spine.
    pub async fn put_batch(&mut self, pairs: Vec<(Bytes, Bytes)>) -> Result<()> {
        self.invalidate_append_state();
        let mut cached: Option<(Vec<u64>, Option<Vec<u8>>)> = None;

        for (key, value) in pairs {
            self.validate_insert_record_fits(&key, &value)?;
            if self.root_page_id == 0 {
                self.put(&key, &value).await?;
                continue;
            }

            let (path, upper_bound) = match cached.take() {
                Some((path, upper_bound))
                    if upper_bound
                        .as_ref()
                        .is_none_or(|upper| key.as_ref() < upper.as_slice()) =>
                {
                    (path, upper_bound)
                }
                _ => {
                    let path = self.path_to_leaf_for_key(&key).await?;
                    let upper_bound = self.exclusive_upper_bound_for_path(&path).await?;
                    (path, upper_bound)
                }
            };

            let leaf_value = self.leaf_value_for(&value).await?;
            let path_for_reuse = path.clone();
            let split = self.put_at_path(path, &key, leaf_value).await?;
            if !split {
                cached = Some((path_for_reuse, upper_bound));
            }
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
        // Parent paths are authoritative for fresh same-session split leaves;
        // their sibling links remain zero until flush.
        let mut path = self.path_to_leaf_for_key(start).await?;
        let mut keys_to_delete: Vec<Vec<u8>> = Vec::new();
        let mut seen_leaves = SeenPageIds::new("leaf_siblings");
        'outer: loop {
            let leaf_page_id = *path.last().expect("non-empty path");
            seen_leaves.insert(leaf_page_id)?;
            let leaf = self.read_leaf(leaf_page_id).await?;
            for (k, _) in &leaf.records {
                if k.as_slice() >= end {
                    break 'outer;
                }
                if k.as_slice() >= start {
                    keys_to_delete.push(k.clone());
                }
            }
            let next_path = self.next_leaf_after(&path).await?;
            match (leaf.right_sibling, next_path) {
                (0, Some(parent_next)) => path = parent_next,
                (0, None) => break,
                (right_sibling, Some(parent_next))
                    if parent_next.last().copied() == Some(right_sibling) =>
                {
                    path = parent_next;
                }
                (right_sibling, parent_next) => {
                    return Err(PagedbError::leaf_sibling_mismatch(
                        leaf_page_id,
                        right_sibling,
                        parent_next.and_then(|path| path.last().copied()),
                    ));
                }
            }
        }
        let count = keys_to_delete.len() as u64;
        for key in keys_to_delete {
            self.delete(&key).await?;
        }
        Ok(count)
    }
}
