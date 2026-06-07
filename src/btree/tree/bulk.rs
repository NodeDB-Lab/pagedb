//! Bulk-load: build a dense tree from sorted pairs without `CoW` overhead.

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::node;

use super::core::BTree;

impl<V: Vfs> BTree<V> {
    /// Bulk-load sorted `(key, value)` pairs into a freshly-created tree
    /// without any `CoW` overhead. The tree must be empty (`root_page_id == 0`).
    ///
    /// All records are first placed into as few leaves as needed, then internal
    /// nodes are built bottom-up. Each page is written exactly once; no freed
    /// pages are generated. The resulting layout is dense and compact.
    ///
    /// Overflow values are NOT supported in bulk-load; callers must ensure all
    /// values fit inline (`value.len()` ≤ `page_size` / 4). For compaction use-
    /// cases, the pairs come from `collect_range` which already resolves
    /// overflow chains into inline bytes.
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

        // Build leaves greedily: pack as many records as fit into each leaf.
        // No sibling pointers yet — we'll wire them up at the end.
        let mut leaves: Vec<(u64, Vec<u8>)> = Vec::new(); // (page_id, first_key)

        let body_cap = node::body_capacity(self.page_size);
        let mut current_leaf = Leaf::new();

        let flush_leaf = |leaf: &Leaf, page_id: u64, next_id: u64| {
            let _ = (leaf, page_id, next_id); // will write below
        };
        let _ = flush_leaf; // suppress unused-variable lint (closure is a placeholder)

        // First pass: group records into leaves.
        let mut leaf_groups: Vec<Vec<(Vec<u8>, Vec<u8>)>> = Vec::new();
        for (k, v) in &pairs {
            let entry_size = {
                let suffix_len = k.len(); // conservative: no prefix compression yet
                2 + suffix_len + 2 + v.len() // slot entry (inline value)
            };
            // Rough check: header + slot_dir entry + record body
            let projected = node::HEADER_LEN
                + (current_leaf.records.len() + 1) * 2
                + current_leaf
                    .records
                    .iter()
                    .map(|(ck, cv)| 2 + ck.len() + cv.encoded_size())
                    .sum::<usize>()
                + entry_size;
            if projected > body_cap && !current_leaf.records.is_empty() {
                leaf_groups.push(
                    std::mem::take(&mut current_leaf.records)
                        .into_iter()
                        .map(|(lk, lv)| {
                            let vbytes = match lv {
                                LeafValue::Inline(b) => b,
                                LeafValue::Overflow { .. } => Vec::new(),
                            };
                            (lk, vbytes)
                        })
                        .collect(),
                );
                current_leaf = Leaf::new();
            }
            current_leaf.upsert(k, LeafValue::Inline(v.clone()));
        }
        if !current_leaf.records.is_empty() {
            leaf_groups.push(
                std::mem::take(&mut current_leaf.records)
                    .into_iter()
                    .map(|(lk, lv)| {
                        let vbytes = match lv {
                            LeafValue::Inline(b) => b,
                            LeafValue::Overflow { .. } => Vec::new(),
                        };
                        (lk, vbytes)
                    })
                    .collect(),
            );
        }

        // Second pass: allocate page_ids and write leaves with correct sibling pointers.
        let n_leaves = leaf_groups.len();
        let page_ids: Vec<u64> = (0..n_leaves).map(|_| self.allocate_page()).collect();

        for (i, group) in leaf_groups.iter().enumerate() {
            let mut leaf = Leaf {
                left_sibling: if i == 0 { 0 } else { page_ids[i - 1] },
                right_sibling: if i + 1 < n_leaves { page_ids[i + 1] } else { 0 },
                records: group
                    .iter()
                    .map(|(k, v)| (k.clone(), LeafValue::Inline(v.clone())))
                    .collect(),
            };
            leaf.records.sort_by(|(a, _), (b, _)| a.cmp(b)); // already sorted
            self.write_leaf(page_ids[i], &leaf).await?;
            let first_key = group.first().map(|(k, _)| k.clone()).unwrap_or_default();
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
