//! Tree navigation: path descent, sibling traversal, and split propagation.

use crate::Result;
use crate::vfs::Vfs;

use crate::btree::internal::{Internal, InternalAccessor, InternalEntry};
use crate::btree::node::NodeKind;
use crate::btree::split::split_internal;

use super::core::BTree;

impl<V: Vfs> BTree<V> {
    /// Given an internal node and a child `page_id`, return the `page_id` of the
    /// NEXT child (to the right), or `None` if `child` is the rightmost. Used by
    /// the parent-mediated scan in [`next_leaf_after`](Self::next_leaf_after).
    fn right_sibling_child(internal: &Internal, child: u64) -> Option<u64> {
        if internal.leftmost_child == child {
            return internal.entries.first().map(|e| e.right_child);
        }
        for (i, e) in internal.entries.iter().enumerate() {
            if e.right_child == child {
                return internal.entries.get(i + 1).map(|ne| ne.right_child);
            }
        }
        None
    }

    pub(super) async fn propagate_split_up(
        &mut self,
        path: Vec<u64>,
        new_left_child: u64,
        new_right_child: u64,
        promoted_key: Vec<u8>,
    ) -> Result<()> {
        let mut child_old = *path.last().expect("non-empty path");
        let mut left_replacement = new_left_child;
        let mut sep_to_insert = promoted_key;
        let mut right_to_insert = new_right_child;
        let mut levels_remaining = path.len() - 1;

        loop {
            if levels_remaining == 0 {
                let new_root_page = self.allocate_page();
                let internal = Internal {
                    leftmost_child: left_replacement,
                    entries: vec![InternalEntry {
                        key: sep_to_insert,
                        right_child: right_to_insert,
                    }],
                };
                self.write_internal(new_root_page, &internal).await?;
                self.root_page_id = new_root_page;
                return Ok(());
            }

            let internal_page = path[levels_remaining - 1];
            let mut internal = self.read_internal(internal_page).await?;

            if internal.leftmost_child == child_old {
                internal.leftmost_child = left_replacement;
            } else {
                for e in &mut internal.entries {
                    if e.right_child == child_old {
                        e.right_child = left_replacement;
                        break;
                    }
                }
            }
            internal.upsert(&sep_to_insert, right_to_insert);

            let new_internal_page = self.allocate_page();
            if !internal.fits(self.page_size) {
                let (left, right, promoted) = split_internal(internal);
                let right_internal_page = self.allocate_page();
                self.write_internal(new_internal_page, &left).await?;
                self.write_internal(right_internal_page, &right).await?;
                self.free_page(internal_page);
                // An internal page that other dirty leaves' parent paths
                // reference has been replaced and freed; remap them. The
                // split case promotes the old internal: keys ≤ promoted live
                // on `new_internal_page`, the rest on `right_internal_page`.
                // For path-remapping (used only to find ancestors to CoW)
                // either replacement is acceptable, so substitute with the
                // left replacement.
                self.remap_dirty_parent_paths(internal_page, new_internal_page);
                child_old = internal_page;
                left_replacement = new_internal_page;
                right_to_insert = right_internal_page;
                sep_to_insert = promoted;
                levels_remaining -= 1;
                continue;
            }

            self.write_internal(new_internal_page, &internal).await?;
            self.free_page(internal_page);
            self.remap_dirty_parent_paths(internal_page, new_internal_page);

            let mut child_old_chain = internal_page;
            let mut child_new_chain = new_internal_page;
            for i in (0..levels_remaining - 1).rev() {
                let p = path[i];
                let mut node = self.read_internal(p).await?;
                if node.leftmost_child == child_old_chain {
                    node.leftmost_child = child_new_chain;
                } else {
                    for e in &mut node.entries {
                        if e.right_child == child_old_chain {
                            e.right_child = child_new_chain;
                            break;
                        }
                    }
                }
                let new_p = self.allocate_page();
                self.write_internal(new_p, &node).await?;
                self.free_page(p);
                self.remap_dirty_parent_paths(p, new_p);
                child_old_chain = p;
                child_new_chain = new_p;
            }
            self.root_page_id = child_new_chain;
            return Ok(());
        }
    }

    /// Substitute every occurrence of `old` with `new` in cached dirty-leaf
    /// parent paths. Used after a split or a spine `CoW` in
    /// [`propagate_split_up`](Self::propagate_split_up) replaces an internal
    /// page that other dirty leaves' paths reference.
    fn remap_dirty_parent_paths(&mut self, old: u64, new: u64) {
        if self.dirty_parent_paths.is_empty() {
            return;
        }
        for path in self.dirty_parent_paths.values_mut() {
            for p in path.iter_mut() {
                if *p == old {
                    *p = new;
                }
            }
        }
    }

    /// Descend from the root to the leaf that would contain `key`, returning
    /// the full path (internal `page_ids` followed by the leaf `page_id`).
    pub(super) async fn path_to_leaf_for_key(&self, key: &[u8]) -> Result<Vec<u64>> {
        let mut path = Vec::new();
        let mut page_id = self.root_page_id;
        loop {
            path.push(page_id);
            // Fresh leaves (from in-txn splits) live only in `fresh_leaves`
            // until flush — the pager has no copy yet. Short-circuit the
            // descent before attempting a pager read.
            if self.fresh_leaves.contains_key(&page_id) {
                return Ok(path);
            }
            let (guard, kind) = self.read_node_guard(page_id).await?;
            if kind == NodeKind::Leaf {
                return Ok(path);
            }
            let next = InternalAccessor::new(guard.body_ref())?.child_for(key);
            drop(guard);
            page_id = next;
        }
    }

    /// Given a `path` ending at a leaf, return the path to the next leaf to
    /// the right (in key order), or `None` if `path` is the rightmost leaf.
    ///
    /// Walks up the path looking for the first ancestor where the current
    /// subtree isn't the rightmost child, then descends the leftmost branch
    /// of the next sibling.
    pub(super) async fn next_leaf_after(&self, path: &[u64]) -> Result<Option<Vec<u64>>> {
        if path.len() < 2 {
            // Root is a leaf; no next leaf.
            return Ok(None);
        }
        let mut child = path[path.len() - 1];
        for i in (0..path.len() - 1).rev() {
            let (guard, _kind) = self.read_node_guard(path[i]).await?;
            let internal = Internal::decode(guard.body_ref())?;
            drop(guard);
            if let Some(next_child) = Self::right_sibling_child(&internal, child) {
                // Build the path: prefix up to `i`, then descend leftmost from `next_child`.
                let mut new_path: Vec<u64> = path[..=i].to_vec();
                let mut cur = next_child;
                loop {
                    new_path.push(cur);
                    // A fresh-from-split leaf has no pager presence yet.
                    if self.fresh_leaves.contains_key(&cur) {
                        return Ok(Some(new_path));
                    }
                    let (g, k) = self.read_node_guard(cur).await?;
                    if k == NodeKind::Leaf {
                        return Ok(Some(new_path));
                    }
                    let internal = Internal::decode(g.body_ref())?;
                    drop(g);
                    cur = internal.leftmost_child;
                }
            }
            child = path[i];
        }
        Ok(None)
    }

    /// Descend from the root taking the rightmost child at every internal
    /// node. Returns the path (internal `page_ids` followed by the rightmost
    /// leaf `page_id`). Used by [`Self::put_append`] to seed the cached
    /// path after invalidation.
    pub(super) async fn path_to_rightmost_leaf(&self) -> Result<Vec<u64>> {
        let mut path = Vec::new();
        let mut page_id = self.root_page_id;
        loop {
            path.push(page_id);
            // Fresh-from-split leaves only live in `fresh_leaves`.
            if self.fresh_leaves.contains_key(&page_id) {
                return Ok(path);
            }
            let (guard, kind) = self.read_node_guard(page_id).await?;
            if kind == NodeKind::Leaf {
                return Ok(path);
            }
            let internal = Internal::decode(guard.body_ref())?;
            drop(guard);
            // Rightmost child of an internal node: the last entry's
            // `right_child`, or `leftmost_child` if the entries list is empty.
            page_id = internal
                .entries
                .last()
                .map_or(internal.leftmost_child, |e| e.right_child);
        }
    }
}
