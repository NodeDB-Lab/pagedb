//! Maintenance walks: rekey under a new epoch and reachable-page collection.

use crate::Result;
use crate::errors::PagedbError;
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
                        // Rewrite root page (v2 OverflowRoot or v1 Overflow).
                        let root_info =
                            overflow::read_root_page(&self.pager, self.realm_id, *ov_root).await?;
                        let root_kind = if root_info.is_v2 {
                            PageKind::OverflowRoot
                        } else {
                            PageKind::Overflow
                        };
                        self.pager
                            .rewrite_page_under_current_epoch(*ov_root, self.realm_id, root_kind)
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
    async fn collect_overflow_chain(&self, root: u64, out: &mut std::collections::BTreeSet<u64>) {
        let mut first = true;
        let mut chain_id = root;
        while chain_id != 0 {
            if !out.insert(chain_id) {
                break;
            }
            let kind = if first {
                first = false;
                PageKind::OverflowRoot
            } else {
                PageKind::Overflow
            };
            let g = match self
                .pager
                .read_main_page(chain_id, self.realm_id, kind)
                .await
            {
                Ok(g) => g,
                Err(PagedbError::ChecksumFailure) => {
                    match self
                        .pager
                        .read_main_page(chain_id, self.realm_id, PageKind::Overflow)
                        .await
                    {
                        Ok(g) => g,
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            };
            let body = g.body();
            if body.len() < 8 {
                break;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&body[..8]);
            chain_id = u64::from_le_bytes(b);
        }
    }
}
