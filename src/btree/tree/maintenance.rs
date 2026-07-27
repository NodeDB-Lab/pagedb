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
    ///
    /// Production rekey always drives [`Self::rekey_walk_unique`] with a shared
    /// map so retained roots are not re-sealed once per root; this single-root
    /// entry point exists so tests can exercise a walk in isolation.
    #[cfg(test)]
    pub async fn rekey_walk(&self) -> Result<u64> {
        self.rekey_walk_unique(&mut BTreeMap::new()).await
    }

    /// Rekey this tree while sharing traversal state with other live roots.
    ///
    /// Copy-on-write snapshots share most of their physical pages, so a caller
    /// rewriting several roots — the live tree plus every root a retained
    /// commit-history row still names — passes one map and each page is
    /// authenticated and re-sealed exactly once. Without it the work is
    /// `O(roots × pages)` of AEAD rather than `O(unique pages)`.
    ///
    /// The map holds each page's *kind*, not just its id, because the two
    /// failure modes are not the same. A page already walked as a node and
    /// referenced again as a node is an ordinary snapshot share and is skipped;
    /// the same id presented under a different role means one of the two
    /// references survived the page being freed and reused, and is reported as
    /// [`CorruptionDetail::PageKindAliased`](crate::errors::CorruptionDetail::PageKindAliased).
    /// A plain id set could not tell them apart.
    ///
    /// Returns the number of pages this call rewrote — pages an earlier walk
    /// already covered are not counted twice.
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
            if let Some(&walked_as) = visited.get(&page_id) {
                match walked_as {
                    PageKind::BTreeLeaf | PageKind::BTreeInternal => continue,
                    other => {
                        // Named for the role, not a kind: which of the two node
                        // kinds this page is has not been read yet, and cannot
                        // be — the alias is decided before any read.
                        return Err(PagedbError::page_kind_aliased(
                            page_id,
                            other.name(),
                            "btree_node",
                        ));
                    }
                }
            }
            // `read_node_guard` is the only accessor that proves the
            // authenticated envelope kind and the encrypted body header agree.
            // This walk both records a page's kind and re-seals the page under
            // it, so taking those two from different sources would let a
            // mis-routed page be laundered into a freshly authenticated one and
            // would leave `visited` describing a kind that is no longer on disk.
            let (guard, node_kind) = self.read_node_guard(page_id).await?;
            let page_kind = match node_kind {
                NodeKind::Leaf => PageKind::BTreeLeaf,
                NodeKind::Internal => PageKind::BTreeInternal,
            };
            visited.insert(page_id, page_kind);

            match node_kind {
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
                        count += self
                            .rekey_overflow_unique(page_id, overflow_root, visited)
                            .await?;
                    }
                }
                NodeKind::Internal => {
                    let node = internal::Internal::decode(guard.body_ref())?;
                    drop(guard);

                    // A zero child id is an absent slot, not a pointer.
                    if node.leftmost_child != 0 {
                        stack.push((page_id, node.leftmost_child));
                    }
                    for entry in &node.entries {
                        if entry.right_child != 0 {
                            stack.push((page_id, entry.right_child));
                        }
                    }
                }
            }

            self.pager
                .rewrite_page_under_current_epoch(page_id, self.realm_id, page_kind)
                .await?;
            count += 1;
        }
        Ok(count)
    }

    /// Rewrite the overflow chain rooted at `root` — referenced by leaf
    /// `leaf_page_id` — returning the number of pages this call rewrote.
    ///
    /// Overflow roots are reference-counted, so a chain reached a second time
    /// through a different leaf (in this tree or in another snapshot's tree)
    /// arrives at the *same* root and is skipped whole. A chain *page* reached
    /// twice therefore cannot be a legitimate share: either the chain loops, or
    /// two distinct roots claim one page. Both mean the chain has no honest
    /// terminator, which is why neither is treated as a stopping condition.
    async fn rekey_overflow_unique(
        &self,
        leaf_page_id: u64,
        root: u64,
        visited: &mut BTreeMap<u64, PageKind>,
    ) -> Result<u64> {
        // Unlike an internal child slot or a chain terminator, zero is not a
        // valid overflow root: an `Overflow` leaf value always owns at least
        // its root page.
        if is_reserved(root) {
            return Err(PagedbError::reserved_page_referenced(leaf_page_id, root));
        }
        if let Some(&walked_as) = visited.get(&root) {
            return match walked_as {
                // Already rewritten with its whole chain, by a leaf holding the
                // other reference to this refcounted value.
                PageKind::OverflowRoot => Ok(0),
                other => Err(PagedbError::page_kind_aliased(
                    root,
                    other.name(),
                    PageKind::OverflowRoot.name(),
                )),
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
            if let Some(&walked_as) = visited.get(&next) {
                return match walked_as {
                    PageKind::Overflow => Err(PagedbError::overflow_chain_cycle(root, next)),
                    other => Err(PagedbError::page_kind_aliased(
                        next,
                        other.name(),
                        PageKind::Overflow.name(),
                    )),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::errors::CorruptionDetail;
    use crate::pager::format::page_kind::PageKind;
    use crate::vfs::memory::MemVfs;
    use crate::{Db, PagedbError, RealmId};

    use super::super::core::BTree;

    const PAGE: usize = 4096;
    const KEK: [u8; 32] = [0x7B; 32];
    const REALM: RealmId = RealmId::new([0x7C; 16]);

    /// A tree deep enough to hold internal nodes, plus one overflow value so
    /// the walk covers both the node and the chain path.
    async fn populated_db() -> Db<MemVfs> {
        let db = Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
            .await
            .unwrap();
        let mut txn = db.begin_write().await.unwrap();
        for index in 0u16..256 {
            txn.put(format!("key-{index:04}").as_bytes(), &index.to_le_bytes())
                .await
                .unwrap();
        }
        txn.put(b"overflowing", &vec![0x33; PAGE * 3])
            .await
            .unwrap();
        txn.commit().await.unwrap();
        db
    }

    async fn data_tree(db: &Db<MemVfs>) -> BTree<MemVfs> {
        let state = db.writer.lock().await;
        BTree::open(
            db.pager.clone(),
            REALM,
            state.root_page_id,
            state.next_page_id,
            db.page_size,
        )
    }

    /// The whole point of the shared map: snapshots overlap almost entirely, so
    /// a second root covering already-walked pages must cost nothing. Without
    /// it, rekey re-authenticates and re-seals every shared page once per
    /// retained root.
    #[tokio::test(flavor = "current_thread")]
    async fn a_second_walk_over_shared_pages_rewrites_nothing() {
        let db = populated_db().await;
        let tree = data_tree(&db).await;

        let mut shared = BTreeMap::new();
        let first = tree.rekey_walk_unique(&mut shared).await.unwrap();
        assert!(
            first > 1,
            "fixture must span more than a single page, walked {first}"
        );
        let recorded = shared.len();

        let second = tree.rekey_walk_unique(&mut shared).await.unwrap();
        assert_eq!(
            second, 0,
            "every page was already covered by the first walk"
        );
        assert_eq!(
            shared.len(),
            recorded,
            "a repeat walk must not discover new pages"
        );
    }

    /// Each walk on its own map does the full work — the dedup above is a
    /// property of the shared map, not of the tree being walked twice.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unshared_walk_covers_every_page_again() {
        let db = populated_db().await;
        let tree = data_tree(&db).await;

        let first = tree.rekey_walk_unique(&mut BTreeMap::new()).await.unwrap();
        let second = tree.rekey_walk().await.unwrap();
        assert_eq!(first, second);
    }

    /// The map records kinds, not just ids, so that a page reached under two
    /// different roles is a reported alias rather than a silent skip. Here a
    /// real overflow root — already walked as `OverflowRoot` — is presented as
    /// a B+ tree root, which is what a freed-and-reused page looks like from
    /// the second reference.
    #[tokio::test(flavor = "current_thread")]
    async fn a_page_reached_under_two_kinds_is_reported_not_skipped() {
        let db = populated_db().await;
        let tree = data_tree(&db).await;

        let mut shared = BTreeMap::new();
        tree.rekey_walk_unique(&mut shared).await.unwrap();
        let (&overflow_root, _) = shared
            .iter()
            .find(|(_, kind)| **kind == PageKind::OverflowRoot)
            .expect("the fixture stores one overflow value");

        let aliased = BTree::open(
            db.pager.clone(),
            REALM,
            overflow_root,
            overflow_root + 1,
            db.page_size,
        );
        let error = aliased.rekey_walk_unique(&mut shared).await.unwrap_err();
        assert!(
            matches!(
                error,
                PagedbError::Corruption(CorruptionDetail::PageKindAliased {
                    page_id,
                    walked_as: "overflow_root",
                    referenced_as: "btree_node",
                }) if page_id == overflow_root
            ),
            "expected an alias naming the page and both roles, got {error:?}"
        );
    }

    /// Rekey re-seals each page under the kind it walked it as. Taking that
    /// kind from the body header while the envelope says otherwise would launder
    /// a mis-routed page into a freshly authenticated one, so the walk must go
    /// through the accessor that proves the two agree.
    #[tokio::test(flavor = "current_thread")]
    async fn a_page_whose_envelope_contradicts_its_body_is_never_re_sealed() {
        let db = populated_db().await;
        let (leaf_page_id, forged) = {
            let state = db.writer.lock().await;
            let tree = BTree::open(
                db.pager.clone(),
                REALM,
                state.root_page_id,
                state.next_page_id,
                db.page_size,
            );
            let mut reachable = std::collections::BTreeSet::new();
            tree.collect_all_page_ids(&mut reachable).await.unwrap();
            let mut leaf = None;
            for &page_id in &reachable {
                if let Ok((_, PageKind::BTreeLeaf)) = db.pager.read_main_node(page_id, REALM).await
                {
                    leaf = Some(page_id);
                    break;
                }
            }
            (leaf.expect("the fixture has leaves"), state.next_page_id)
        };

        // Copy a live leaf's bytes under the internal-node envelope kind: the
        // body stays structurally valid, so the only defect is the routing.
        let guard = db
            .pager
            .read_main_node(leaf_page_id, REALM)
            .await
            .unwrap()
            .0;
        let body = guard.body_ref().to_vec();
        drop(guard);
        db.pager
            .write_main_page(forged, REALM, PageKind::BTreeInternal, &body)
            .await
            .unwrap();
        db.pager.flush_main(REALM).await.unwrap();
        db.pager.reset_main_pages();

        let tree = BTree::open(db.pager.clone(), REALM, forged, forged + 1, db.page_size);
        let error = tree.rekey_walk().await.unwrap_err();
        assert!(
            matches!(
                error,
                PagedbError::Corruption(CorruptionDetail::NodeKindMismatch {
                    page_id: Some(page_id),
                    expected: "internal",
                    found: "leaf",
                }) if page_id == forged
            ),
            "expected the kind disagreement to stop the walk, got {error:?}"
        );
    }
}
