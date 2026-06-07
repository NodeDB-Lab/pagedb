//! Flush: materialize the dirty-leaf cache into the pager via `CoW`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::Result;
use crate::vfs::Vfs;

use crate::btree::leaf::Leaf;

use super::core::BTree;

impl<V: Vfs> BTree<V> {
    pub async fn flush(&mut self) -> Result<()> {
        self.flush_dirty_leaves().await?;
        self.pager.flush_main(self.realm_id).await
    }

    /// Materialize the dirty-leaf cache into the pager (`CoW` new pages, update
    /// spine, update `root_page_id`) WITHOUT issuing a pager-level flush /
    /// fsync. Callers that bundle multiple trees into a single commit use this
    /// to coalesce all page writes behind one `pager.flush_main` fsync.
    pub async fn materialize_dirty(&mut self) -> Result<()> {
        self.flush_dirty_leaves().await
    }

    /// Materialize the dirty-leaf cache into the buffer pool. For each leaf
    /// cached at its on-disk `page_id`, allocate a fresh page (`CoW`), encode +
    /// write to the new page, and record the redirect. Then walk only the
    /// affected ancestors (collected from per-leaf parent paths) bottom-up,
    /// `CoW`'ing each internal that points at a redirected child. Finally
    /// drain `fresh_leaves` (created by splits during this txn) — they're
    /// already pinned to fresh page ids on a `CoW`'d spine, so we just encode
    /// + write them at those ids without any redirect work.
    async fn flush_dirty_leaves(&mut self) -> Result<()> {
        // Materialize fresh-from-split leaves first. They don't participate
        // in the redirect/spine walk; just encode + write at their pinned
        // page ids. Doing them upfront also ensures the pager has every
        // fresh page before any subsequent `read_node_guard` in this flush
        // touches the spine.
        if !self.fresh_leaves.is_empty() {
            let fresh: Vec<(u64, Leaf)> = self.fresh_leaves.drain().collect();
            for (page_id, leaf) in fresh {
                self.write_leaf(page_id, &leaf).await?;
            }
        }
        if self.dirty_leaves.is_empty() {
            return Ok(());
        }
        let dirties: Vec<(u64, Leaf)> = self.dirty_leaves.drain().collect();
        let parent_paths: HashMap<u64, Vec<u64>> = self.dirty_parent_paths.drain().collect();
        let mut redirects: HashMap<u64, u64> = HashMap::with_capacity(dirties.len());
        for (old_page_id, leaf) in dirties {
            let new_page_id = self.allocate_page();
            self.write_leaf(new_page_id, &leaf).await?;
            redirects.insert(old_page_id, new_page_id);
            // The old leaf page goes through `scheduled_frees` →
            // `drain_freed`; the caller drains it into the deferred-free queue.
        }
        // Group affected internals by depth (index in the path from the root).
        let mut internals_by_depth: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();
        for path in parent_paths.values() {
            for (depth, &page_id) in path.iter().enumerate() {
                internals_by_depth.entry(depth).or_default().insert(page_id);
            }
        }
        // Process deepest-first so each parent's children are already
        // redirected by the time the parent is rewritten.
        let mut spine_frees: Vec<u64> = Vec::new();
        for page_ids in internals_by_depth.values().rev() {
            for &old_page_id in page_ids {
                let mut internal = self.read_internal(old_page_id).await?;
                let mut changed = false;
                if let Some(&new_child) = redirects.get(&internal.leftmost_child) {
                    internal.leftmost_child = new_child;
                    changed = true;
                }
                for e in &mut internal.entries {
                    if let Some(&new_child) = redirects.get(&e.right_child) {
                        e.right_child = new_child;
                        changed = true;
                    }
                }
                if !changed {
                    continue;
                }
                let new_page_id = self.allocate_page();
                self.write_internal(new_page_id, &internal).await?;
                redirects.insert(old_page_id, new_page_id);
                spine_frees.push(old_page_id);
            }
        }
        if let Some(&new_root) = redirects.get(&self.root_page_id) {
            self.root_page_id = new_root;
        }
        for pid in spine_frees {
            self.free_page(pid);
        }
        Ok(())
    }

    /// Drain and return all `page_ids` that were freed during this tree's
    /// mutation session, plus any leaf pages scheduled for freeing at the
    /// upcoming `flush`. After this call, both `self.freed` and
    /// `self.scheduled_frees` are empty.
    pub fn drain_freed(&mut self) -> Vec<u64> {
        let mut out = std::mem::take(&mut self.freed);
        out.append(&mut self.scheduled_frees);
        out
    }
}
