//! Bulk-load: build a dense tree from sorted pairs without `CoW` overhead.

use std::sync::Arc;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::node;
use crate::btree::overflow;

use super::core::BTree;

impl<V: Vfs> BTree<V> {
    /// Bulk-load sorted `(key, value)` pairs into a freshly-created tree
    /// without any `CoW` overhead. The tree must be empty (`root_page_id == 0`).
    ///
    /// Values larger than the inline threshold (`page_size / 4`) are spilled to
    /// overflow chains, exactly as the `put` path does, so a dense repack
    /// reproduces the original storage shape. Records are then packed into as few
    /// leaves as needed and internal nodes are built bottom-up. Each leaf/internal
    /// page is written exactly once; the layout is dense and compact.
    ///
    /// Returns `Err` if the tree is not empty.
    #[allow(clippy::too_many_lines)]
    pub async fn bulk_load(&mut self, pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        if self.root_page_id != 0 {
            return Err(PagedbError::Io(std::io::Error::other(
                "bulk_load: tree must be empty",
            )));
        }
        if pairs.is_empty() {
            return Ok(());
        }

        // Resolve each value to its stored form, spilling values past the inline
        // threshold to overflow chains (same threshold as `put`). Inlining an
        // oversized value would exceed leaf capacity and fail the encode.
        let realm = self.realm_id;
        let ps = self.page_size;
        let pager = Arc::clone(&self.pager);
        let inline_threshold = overflow::inline_value_threshold(ps);
        let mut records: Vec<(Vec<u8>, LeafValue)> = Vec::with_capacity(pairs.len());
        for (k, v) in pairs {
            let value = if v.len() > inline_threshold {
                let total_len = v.len() as u64;
                let root_page_id =
                    overflow::write_chain(&pager, realm, &v, ps, &mut || self.allocate_page())
                        .await?;
                LeafValue::Overflow {
                    total_len,
                    root_page_id,
                }
            } else {
                LeafValue::Inline(v)
            };
            records.push((k, value));
        }

        let body_cap = node::body_capacity(ps);

        // First pass: group records into leaves, sized by encoded record width.
        let mut leaf_groups: Vec<Vec<(Vec<u8>, LeafValue)>> = Vec::new();
        let mut current: Vec<(Vec<u8>, LeafValue)> = Vec::new();
        for (k, value) in records {
            // New record's body contribution: suffix-len field + key + value.
            // (No prefix compression at build time, so suffix == full key.)
            let entry_size = 2 + k.len() + value.encoded_size();
            let projected = node::HEADER_LEN
                + (current.len() + 1) * 2
                + current
                    .iter()
                    .map(|(ck, cv)| 2 + ck.len() + cv.encoded_size())
                    .sum::<usize>()
                + entry_size;
            if projected > body_cap && !current.is_empty() {
                leaf_groups.push(std::mem::take(&mut current));
            }
            current.push((k, value));
        }
        if !current.is_empty() {
            leaf_groups.push(current);
        }

        // Second pass: allocate page ids and write leaves with sibling links.
        // Input is sorted and grouping preserves order, so each leaf's records
        // are already in key order.
        let mut leaves: Vec<(u64, Vec<u8>)> = Vec::new(); // (page_id, first_key)
        let n_leaves = leaf_groups.len();
        let page_ids: Vec<u64> = (0..n_leaves).map(|_| self.allocate_page()).collect();

        for (i, group) in leaf_groups.into_iter().enumerate() {
            let first_key = group.first().map(|(k, _)| k.clone()).unwrap_or_default();
            let leaf = Leaf {
                left_sibling: if i == 0 { 0 } else { page_ids[i - 1] },
                right_sibling: if i + 1 < n_leaves { page_ids[i + 1] } else { 0 },
                records: group,
            };
            self.write_leaf(page_ids[i], &leaf).await?;
            leaves.push((page_ids[i], first_key));
        }

        if leaves.len() == 1 {
            self.root_page_id = leaves[0].0;
            return Ok(());
        }

        // Build internal nodes bottom-up.
        // Each level has a list of (page_id, separator_key) for each node.
        let mut current_level: Vec<(u64, Vec<u8>)> = leaves;

        loop {
            if current_level.len() == 1 {
                self.root_page_id = current_level[0].0;
                break;
            }

            // Group children into internal nodes. Each internal node can hold
            // a limited number of children.
            let mut new_level: Vec<(u64, Vec<u8>)> = Vec::new();
            let mut remaining = &current_level[..];

            while !remaining.is_empty() {
                // Determine how many children fit in one internal node.
                // An internal entry is: key_len (2) + key + child_page_id (8).
                // Header is 24 bytes. Slot directory: 2 bytes per entry.
                // Leftmost child takes no key slot.
                let mut count = 1usize; // leftmost child
                let mut used = node::HEADER_LEN;
                for item in remaining.iter().skip(1) {
                    let sep_key = &item.1;
                    let entry_bytes = 2 + sep_key.len() + 8 + 2; // record + slot
                    if used + entry_bytes > body_cap {
                        break;
                    }
                    used += entry_bytes;
                    count += 1;
                }
                let chunk = &remaining[..count];
                remaining = &remaining[count..];

                let leftmost_child = chunk[0].0;
                let entries: Vec<crate::btree::internal::InternalEntry> = chunk[1..]
                    .iter()
                    .map(|(pid, sep)| crate::btree::internal::InternalEntry {
                        key: sep.clone(),
                        right_child: *pid,
                    })
                    .collect();

                let internal = crate::btree::internal::Internal {
                    leftmost_child,
                    entries,
                };
                let pid = self.allocate_page();
                self.write_internal(pid, &internal).await?;
                // Separator for this node: the first key of leftmost child.
                let sep = chunk[0].1.clone();
                new_level.push((pid, sep));
            }

            current_level = new_level;
        }

        Ok(())
    }
}
