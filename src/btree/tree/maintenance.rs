//! Maintenance walks: rekey under a new epoch and reachable-page collection.

use crate::Result;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;

use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::node::{NodeKind, read_header};
use crate::btree::{internal, overflow};

use super::core::BTree;

impl<V: Vfs> BTree<V> {
    /// Walk every page reachable from `self.root_page_id` (internal nodes,
    /// leaves, overflow chains) and rewrite each one under the pager's current
    /// `mk_epoch`. Pages are read via epoch-routing (so old-epoch pages decrypt
    /// correctly) and marked dirty so the next flush re-seals them under the
    /// new epoch.
    ///
    /// Returns the count of pages touched.
    pub async fn rekey_walk(&self) -> Result<u64> {
        if self.root_page_id == 0 {
            return Ok(0);
        }
        let mut stack: Vec<u64> = vec![self.root_page_id];
        let mut count: u64 = 0;
        while let Some(page_id) = stack.pop() {
            // Determine kind by reading the node under its own header kind byte.
            let (is_leaf, body_bytes) = {
                let (g, _page_kind) = self.pager.read_main_node(page_id, self.realm_id).await?;
                let body = g.body();
                let header = read_header(&body)?;
                let is_leaf = header.kind == NodeKind::Leaf;
                (is_leaf, body.to_vec())
            };

            if is_leaf {
                // Collect overflow chains referenced by this leaf.
                let leaf = Leaf::decode(&body_bytes)?;
                for (_k, v) in &leaf.records {
                    if let LeafValue::Overflow {
                        root_page_id: ov_root,
                        ..
                    } = v
                    {
                        // Rewrite the root page (`PageKind::OverflowRoot`).
                        let root_info =
                            overflow::read_root_page(&self.pager, self.realm_id, *ov_root).await?;
                        self.pager
                            .rewrite_page_under_current_epoch(
                                *ov_root,
                                self.realm_id,
                                PageKind::OverflowRoot,
                            )
                            .await?;
                        count += 1;
                        // Walk and rewrite chain pages (always PageKind::Overflow).
                        let mut next = root_info.next;
                        while next != 0 {
                            let ov_guard = self
                                .pager
                                .read_main_page(next, self.realm_id, PageKind::Overflow)
                                .await?;
                            let ov_body = ov_guard.body();
                            let (ov_next, _) = overflow::decode_overflow(&ov_body)?;
                            drop(ov_guard);
                            self.pager
                                .rewrite_page_under_current_epoch(
                                    next,
                                    self.realm_id,
                                    PageKind::Overflow,
                                )
                                .await?;
                            count += 1;
                            next = ov_next;
                        }
                    }
                }
                // Rewrite the leaf page.
                self.pager
                    .rewrite_page_under_current_epoch(page_id, self.realm_id, PageKind::BTreeLeaf)
                    .await?;
                count += 1;
            } else {
                // Internal node: push children onto stack.
                let internal = internal::Internal::decode(&body_bytes)?;
                stack.push(internal.leftmost_child);
                for entry in &internal.entries {
                    stack.push(entry.right_child);
                }
                // Rewrite the internal page.
                self.pager
                    .rewrite_page_under_current_epoch(
                        page_id,
                        self.realm_id,
                        PageKind::BTreeInternal,
                    )
                    .await?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Collect all page IDs reachable from this tree's root (internal nodes,
    /// leaves, overflow chains) into `out`. Used by the deep-walk integrity
    /// checker to identify orphan pages.
    #[allow(clippy::too_many_lines)]
    pub async fn collect_all_page_ids(
        &self,
        out: &mut std::collections::BTreeSet<u64>,
    ) -> Result<()> {
        if self.root_page_id == 0 {
            return Ok(());
        }
        let mut stack: Vec<u64> = vec![self.root_page_id];
        while let Some(page_id) = stack.pop() {
            if !out.insert(page_id) {
                // Already visited.
                continue;
            }
            let (is_leaf, body_bytes) = {
                match self.pager.read_main_node(page_id, self.realm_id).await {
                    Ok((g, _page_kind)) => {
                        let body = g.body();
                        let header = read_header(&body)?;
                        let is_leaf = header.kind == NodeKind::Leaf;
                        (is_leaf, body.to_vec())
                    }
                    Err(_) => continue, // unreadable — best effort
                }
            };

            if is_leaf {
                let Ok(leaf) = Leaf::decode(&body_bytes) else {
                    continue;
                };
                for (_k, v) in &leaf.records {
                    if let LeafValue::Overflow {
                        root_page_id: ov_root,
                        ..
                    } = v
                    {
                        self.collect_overflow_chain(*ov_root, out).await;
                    }
                }
            } else {
                // Internal node: push child page IDs.
                let Ok(internal) = internal::Internal::decode(&body_bytes) else {
                    continue;
                };
                if internal.leftmost_child != 0 {
                    stack.push(internal.leftmost_child);
                }
                for entry in &internal.entries {
                    if entry.right_child != 0 {
                        stack.push(entry.right_child);
                    }
                }
            }
        }
        Ok(())
    }

    /// Walk an overflow chain starting at `root` and insert all page IDs into
    /// `out`. Best-effort: stops on any read failure.
    ///
    /// The `next` pointer lives at different offsets by page type: the root
    /// (`OverflowRoot`) is laid out `refcount[4] || next[8] || …`, so its next is
    /// at byte 4; a chain page (`Overflow`) is laid out `next[8] || …`, so its
    /// next is at byte 0. Reading byte 0 uniformly would decode the root's
    /// `refcount` (1 for a single-owner value) as the next page id — spuriously
    /// chaining to reserved page 1.
    async fn collect_overflow_chain(&self, root: u64, out: &mut std::collections::BTreeSet<u64>) {
        let mut chain_id = root;
        let mut first = true;
        while chain_id != 0 {
            if !out.insert(chain_id) {
                break;
            }
            let (kind, next_off) = if first {
                (PageKind::OverflowRoot, 4usize) // root: next after refcount[4]
            } else {
                (PageKind::Overflow, 0usize) // chain page: next at byte 0
            };
            first = false;
            let Ok(g) = self
                .pager
                .read_main_page(chain_id, self.realm_id, kind)
                .await
            else {
                break;
            };
            let body = g.body();
            if body.len() < next_off + 8 {
                break;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&body[next_off..next_off + 8]);
            chain_id = u64::from_le_bytes(b);
        }
    }

    /// Strict structural walk from the root: return a description of the FIRST
    /// dangling pointer — an internal child that is reserved / Free / unreadable
    /// as a node, or a leaf `Overflow` root that is reserved or unreadable.
    /// `None` = structurally intact. Unlike best-effort `collect_all_page_ids`,
    /// any anomaly is a violation, so the per-commit invariant can pinpoint the
    /// exact commit that introduces a use-after-free.
    pub async fn find_dangling(&self) -> Option<String> {
        if self.root_page_id == 0 {
            return None;
        }
        let mut stack: Vec<(u64, u64)> = vec![(0, self.root_page_id)];
        let mut seen = std::collections::BTreeSet::new();
        while let Some((parent, page_id)) = stack.pop() {
            if page_id < 4 {
                return Some(format!(
                    "internal {parent} -> RESERVED child page {page_id}"
                ));
            }
            if !seen.insert(page_id) {
                continue;
            }
            let (g, _kind) = match self.pager.read_main_node(page_id, self.realm_id).await {
                Ok(v) => v,
                Err(e) => {
                    return Some(format!(
                        "internal {parent} -> child page {page_id} UNREADABLE as node ({e:?}) \
                         — freed/reused (use-after-free)"
                    ));
                }
            };
            let body = g.body();
            let Ok(header) = read_header(&body) else {
                return Some(format!("page {page_id} (parent {parent}) bad node header"));
            };
            if header.kind == NodeKind::Leaf {
                let Ok(leaf) = Leaf::decode(&body) else {
                    return Some(format!("leaf {page_id} (parent {parent}) decode failed"));
                };
                for (k, v) in &leaf.records {
                    if let LeafValue::Overflow { root_page_id, .. } = v {
                        // Walk the FULL overflow chain: every page and every
                        // next-pointer must be a real page (>= 4). A reserved or
                        // unreadable link means a chain page was freed/reused
                        // while still linked (use-after-free).
                        let mut chain = *root_page_id;
                        let mut first = true;
                        let mut chain_seen = std::collections::BTreeSet::new();
                        while chain != 0 {
                            if chain < 4 {
                                return Some(format!(
                                    "leaf {page_id} (parent {parent}) key {:02x?} overflow chain \
                                     -> RESERVED page {chain} (use-after-free)",
                                    &k[..k.len().min(8)]
                                ));
                            }
                            if !chain_seen.insert(chain) {
                                return Some(format!(
                                    "leaf {page_id} (parent {parent}) overflow chain CYCLE at {chain}"
                                ));
                            }
                            // root (`OverflowRoot`): next after refcount[4];
                            // chain page (`Overflow`): next at byte 0.
                            let (kind, next_off, what) = if first {
                                (PageKind::OverflowRoot, 4usize, "root")
                            } else {
                                (PageKind::Overflow, 0usize, "chain page")
                            };
                            first = false;
                            let cg = match self
                                .pager
                                .read_main_page(chain, self.realm_id, kind)
                                .await
                            {
                                Ok(cg) => cg,
                                Err(e) => {
                                    return Some(format!(
                                        "leaf {page_id} (parent {parent}) overflow {what} {chain} \
                                         UNREADABLE ({e:?}) — freed/reused"
                                    ));
                                }
                            };
                            let cbody = cg.body();
                            if cbody.len() < next_off + 8 {
                                break;
                            }
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&cbody[next_off..next_off + 8]);
                            chain = u64::from_le_bytes(b);
                        }
                    }
                }
            } else {
                let Ok(node) = internal::Internal::decode(&body) else {
                    return Some(format!(
                        "internal {page_id} (parent {parent}) decode failed"
                    ));
                };
                drop(g);
                if node.leftmost_child != 0 {
                    stack.push((page_id, node.leftmost_child));
                }
                for e in &node.entries {
                    if e.right_child != 0 {
                        stack.push((page_id, e.right_child));
                    }
                }
            }
        }
        None
    }
}
