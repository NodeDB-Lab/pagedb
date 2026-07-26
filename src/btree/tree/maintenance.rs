//! Maintenance walks: rekey under a new epoch and reachable-page collection.

use std::collections::BTreeMap;

use crate::Result;
use crate::errors::PagedbError;
use crate::pager::format::page_kind::PageKind;
use crate::pager::page_space::is_reserved;
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
        self.rekey_walk_unique(&mut BTreeMap::new()).await
    }

    /// Rekey this tree while sharing traversal state with other live roots.
    ///
    /// Retained snapshots commonly share most of their pages. A caller walking
    /// several roots supplies one page-kind map so each physical page is
    /// authenticated and rewritten exactly once without hiding a cross-kind
    /// alias.
    pub(crate) async fn rekey_walk_unique(
        &self,
        visited: &mut BTreeMap<u64, PageKind>,
    ) -> Result<u64> {
        if self.root_page_id == 0 {
            return Ok(0);
        }
        let mut stack: Vec<(u64, u64)> = vec![(0, self.root_page_id)];
        let mut count: u64 = 0;
        while let Some((parent_page_id, page_id)) = stack.pop() {
            if is_reserved(page_id) {
                return Err(PagedbError::reserved_page_referenced(
                    parent_page_id,
                    page_id,
                ));
            }
            if let Some(kind) = visited.get(&page_id) {
                match kind {
                    PageKind::BTreeLeaf | PageKind::BTreeInternal => continue,
                    _ => return Err(PagedbError::IllegalPageKind),
                }
            }
            // Determine kind by reading the node under its own header kind byte.
            let (is_leaf, page_kind, body_bytes) = {
                let (g, page_kind) = self.pager.read_main_node(page_id, self.realm_id).await?;
                let body = g.body();
                let header = read_header(&body)?;
                let is_leaf = header.kind == NodeKind::Leaf;
                (is_leaf, page_kind, body.to_vec())
            };
            visited.insert(page_id, page_kind);

            if is_leaf {
                // Collect overflow chains referenced by this leaf.
                let leaf = Leaf::decode(&body_bytes)?;
                for (_k, v) in &leaf.records {
                    if let LeafValue::Overflow {
                        root_page_id: ov_root,
                        ..
                    } = v
                    {
                        count += self
                            .rekey_overflow_unique(page_id, *ov_root, visited)
                            .await?;
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
                if internal.leftmost_child != 0 {
                    stack.push((page_id, internal.leftmost_child));
                }
                for entry in &internal.entries {
                    if entry.right_child != 0 {
                        stack.push((page_id, entry.right_child));
                    }
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

    async fn rekey_overflow_unique(
        &self,
        leaf_page_id: u64,
        root: u64,
        visited: &mut BTreeMap<u64, PageKind>,
    ) -> Result<u64> {
        if is_reserved(root) {
            return Err(PagedbError::reserved_page_referenced(leaf_page_id, root));
        }
        if let Some(kind) = visited.get(&root) {
            return match kind {
                PageKind::OverflowRoot => Ok(0),
                _ => Err(PagedbError::IllegalPageKind),
            };
        }
        visited.insert(root, PageKind::OverflowRoot);

        let root_info = overflow::read_root_page(&self.pager, self.realm_id, root).await?;
        self.pager
            .rewrite_page_under_current_epoch(root, self.realm_id, PageKind::OverflowRoot)
            .await?;
        let mut count = 1;
        let mut next = root_info.next;
        while next != 0 {
            if is_reserved(next) {
                return Err(PagedbError::reserved_page_referenced(root, next));
            }
            if let Some(kind) = visited.get(&next) {
                return match kind {
                    PageKind::Overflow => Err(PagedbError::overflow_chain_cycle(root, next)),
                    _ => Err(PagedbError::IllegalPageKind),
                };
            }
            visited.insert(next, PageKind::Overflow);
            let guard = self
                .pager
                .read_main_page(next, self.realm_id, PageKind::Overflow)
                .await?;
            let (following, _) = overflow::decode_overflow(guard.body_ref())?;
            drop(guard);
            self.pager
                .rewrite_page_under_current_epoch(next, self.realm_id, PageKind::Overflow)
                .await?;
            count += 1;
            next = following;
        }
        Ok(count)
    }

    /// Collect all page IDs reachable from this tree's root (internal nodes,
    /// leaves, overflow chains) into `out`. Used by the deep-walk integrity
    /// checker to identify orphan pages.
    ///
    /// Authoritative, not best-effort: `Ok(())` means every reachable node and
    /// overflow page authenticated as its own kind, decoded structurally, and
    /// pointed only at allocatable pages. Anything else is a corruption error,
    /// because a partial set that its caller cannot distinguish from a complete
    /// one turns every live page into a false orphan report — and, worse, reads
    /// as a clean bill of health.
    pub async fn collect_all_page_ids(
        &self,
        out: &mut std::collections::BTreeSet<u64>,
    ) -> Result<()> {
        if self.root_page_id == 0 {
            return Ok(());
        }
        // Track traversal separately from `out`. `out` is the caller's
        // accumulator across every tree in the database and arrives pre-seeded
        // with the reserved pages, so doubling it as the visited set would let
        // whatever the caller happened to put in it silently truncate this
        // walk — the walk's own progress must not depend on that.
        let mut visited = std::collections::BTreeSet::new();
        let mut stack: Vec<(u64, u64)> = vec![(0, self.root_page_id)];

        while let Some((parent_page_id, page_id)) = stack.pop() {
            if is_reserved(page_id) {
                return Err(PagedbError::reserved_page_referenced(
                    parent_page_id,
                    page_id,
                ));
            }
            if !visited.insert(page_id) {
                continue;
            }
            out.insert(page_id);

            let (guard, kind) = self.read_node_guard(page_id).await?;
            match kind {
                NodeKind::Leaf => {
                    let leaf = Leaf::decode(guard.body_ref())?;
                    let overflow_roots: Vec<u64> = leaf
                        .records
                        .iter()
                        .filter_map(|(_, value)| match value {
                            LeafValue::Overflow { root_page_id, .. } => Some(*root_page_id),
                            LeafValue::Inline(_) => None,
                        })
                        .collect();
                    drop(guard);

                    for overflow_root in overflow_roots {
                        self.collect_overflow_chain(page_id, overflow_root, &mut visited, out)
                            .await?;
                    }
                }
                NodeKind::Internal => {
                    let internal = internal::Internal::decode(guard.body_ref())?;
                    drop(guard);

                    // A zero child id is an absent slot, not a pointer.
                    if internal.leftmost_child != 0 {
                        stack.push((page_id, internal.leftmost_child));
                    }
                    for entry in &internal.entries {
                        if entry.right_child != 0 {
                            stack.push((page_id, entry.right_child));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Walk the overflow chain rooted at `root` — referenced by leaf
    /// `leaf_page_id` — and insert every page ID into `out`.
    ///
    /// Authoritative on the same terms as [`Self::collect_all_page_ids`]. A
    /// repeated page is reported as a cycle rather than treated as the end of
    /// the chain: the two are indistinguishable to a caller that just stops
    /// walking, and only one of them is a healthy tree.
    ///
    /// `visited` is the traversal's tree-wide page set. Overflow pages and node
    /// pages draw from the same id space, so one set both deduplicates a chain
    /// shared by several refcounting leaves and catches a chain that loops back
    /// into the node graph.
    async fn collect_overflow_chain(
        &self,
        leaf_page_id: u64,
        root: u64,
        visited: &mut std::collections::BTreeSet<u64>,
        out: &mut std::collections::BTreeSet<u64>,
    ) -> Result<()> {
        // Unlike an internal child slot or a chain terminator, zero is not a
        // valid overflow root: an `Overflow` leaf value always owns at least
        // its root page.
        if is_reserved(root) {
            return Err(PagedbError::reserved_page_referenced(leaf_page_id, root));
        }
        if !visited.insert(root) {
            // Already walked — a value whose chain is shared by refcount.
            return Ok(());
        }
        out.insert(root);

        let info = overflow::read_root_page(&self.pager, self.realm_id, root).await?;
        let mut chain_id = info.next;

        while chain_id != 0 {
            if is_reserved(chain_id) {
                return Err(PagedbError::reserved_page_referenced(root, chain_id));
            }
            if !visited.insert(chain_id) {
                return Err(PagedbError::overflow_chain_cycle(root, chain_id));
            }
            out.insert(chain_id);

            let guard = self
                .pager
                .read_main_page(chain_id, self.realm_id, PageKind::Overflow)
                .await?;
            let body = guard.body();
            let (next, _) = overflow::decode_overflow(&body)?;
            chain_id = next;
        }

        Ok(())
    }

    /// Strict structural walk from the root: return a description of the FIRST
    /// dangling pointer — an internal child that is reserved / Free / unreadable
    /// as a node, or a leaf `Overflow` root that is reserved or unreadable.
    /// `None` = structurally intact. It returns the first anomaly so the
    /// per-commit invariant can pinpoint the exact commit that introduces a
    /// use-after-free.
    pub async fn find_dangling(&self) -> Option<String> {
        if self.root_page_id == 0 {
            return None;
        }
        let mut stack: Vec<(u64, u64)> = vec![(0, self.root_page_id)];
        let mut seen = std::collections::BTreeSet::new();
        while let Some((parent, page_id)) = stack.pop() {
            if is_reserved(page_id) {
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
                    if let LeafValue::Overflow { root_page_id, .. } = v
                        && let Some(desc) = self
                            .find_dangling_in_overflow(page_id, parent, k, *root_page_id)
                            .await
                    {
                        return Some(desc);
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

    /// Walk the full overflow chain rooted at `root` — held by key `key` in
    /// leaf `page_id` — and describe the first anomaly, if any.
    ///
    /// Every page and every next-pointer must be allocatable. A reserved or
    /// unreadable link means a chain page was freed and reused while still
    /// linked. Zero terminates a chain but can never *be* one: an `Overflow`
    /// value owns at least its root page.
    async fn find_dangling_in_overflow(
        &self,
        page_id: u64,
        parent: u64,
        key: &[u8],
        root: u64,
    ) -> Option<String> {
        let key_prefix = &key[..key.len().min(8)];
        if root == 0 {
            return Some(format!(
                "leaf {page_id} (parent {parent}) key {key_prefix:02x?} overflow value has no \
                 root page"
            ));
        }

        let mut chain = root;
        let mut first = true;
        let mut chain_seen = std::collections::BTreeSet::new();
        while chain != 0 {
            if is_reserved(chain) {
                return Some(format!(
                    "leaf {page_id} (parent {parent}) key {key_prefix:02x?} overflow chain -> \
                     RESERVED page {chain} (use-after-free)"
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
            let guard = match self.pager.read_main_page(chain, self.realm_id, kind).await {
                Ok(guard) => guard,
                Err(e) => {
                    return Some(format!(
                        "leaf {page_id} (parent {parent}) overflow {what} {chain} UNREADABLE \
                         ({e:?}) — freed/reused"
                    ));
                }
            };
            let body = guard.body();
            if body.len() < next_off + 8 {
                break;
            }
            let mut next = [0u8; 8];
            next.copy_from_slice(&body[next_off..next_off + 8]);
            chain = u64::from_le_bytes(next);
        }
        None
    }
}
