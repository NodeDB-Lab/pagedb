//! Read-path operations: point lookups and value resolution.

use std::sync::Arc;

use crate::pager::{PageGuard, Pager};
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use crate::btree::internal::InternalAccessor;
use crate::btree::leaf::{Leaf, LeafAccessor, LeafValue, LeafValueRef};
use crate::btree::node::NodeKind;
use crate::btree::overflow;

use super::core::BTree;

impl<V: Vfs> BTree<V> {
    /// Get a value by key. Returns `None` if not found.
    ///
    /// Zero-allocation tree descent: each level reads the page through a
    /// [`PageGuard`], builds a borrowed accessor over the decrypted body, and
    /// either descends or extracts the value. The only allocation on the hit
    /// path is the final owned `Vec<u8>` copy of the inline value (or the
    /// overflow chain reassembly for large values).
    pub async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.root_page_id == 0 {
            return Ok(None);
        }
        // Root could itself be a fresh leaf (single-leaf tree mutated in
        // this txn). Pull the value from the cache instead of the pager.
        if let Some(leaf) = self.fresh_leaves.get(&self.root_page_id) {
            return Self::value_from_cached_leaf(&self.pager, self.realm_id, leaf, key).await;
        }
        let (root_guard, root_kind) = self.read_node_guard(self.root_page_id).await?;
        self.get_from_node(key, self.root_page_id, &root_guard, root_kind)
            .await
    }

    /// Resolve `key` against an in-memory `Leaf` (from `fresh_leaves` /
    /// `dirty_leaves`), following any overflow chain via the pager.
    async fn value_from_cached_leaf(
        pager: &Arc<Pager<V>>,
        realm_id: RealmId,
        leaf: &Leaf,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        match leaf.get(key) {
            None => Ok(None),
            Some(LeafValue::Inline(v)) => Ok(Some(v.clone())),
            Some(LeafValue::Overflow {
                total_len,
                root_page_id,
            }) => {
                let v = overflow::read_chain(pager, realm_id, *root_page_id, *total_len).await?;
                Ok(Some(v))
            }
        }
    }

    /// Variant of [`get`](Self::get) that takes a caller-owned, already-pinned
    /// root [`PageGuard`]. Lets read transactions cache the root for the
    /// lifetime of the txn so subsequent gets skip the root cache lookup.
    pub async fn get_with_cached_root(
        &self,
        key: &[u8],
        root_guard: &PageGuard,
        root_kind: NodeKind,
    ) -> Result<Option<Vec<u8>>> {
        if self.root_page_id == 0 {
            return Ok(None);
        }
        self.get_from_node(key, self.root_page_id, root_guard, root_kind)
            .await
    }

    /// Descend from `start_guard` (the page at `start_page_id`) toward a
    /// leaf, extracting the value at `key` if present. Consults the
    /// dirty-leaf cache at the leaf level — within a write txn, leaves
    /// mutated by `put`/`delete` shadow the buffer-pool bytes.
    async fn get_from_node(
        &self,
        key: &[u8],
        start_page_id: u64,
        start_guard: &PageGuard,
        start_kind: NodeKind,
    ) -> Result<Option<Vec<u8>>> {
        // Handle the first level using the borrowed guard.
        let next_page_id = match start_kind {
            NodeKind::Leaf => {
                return self
                    .extract_leaf_value(key, start_page_id, start_guard)
                    .await;
            }
            NodeKind::Internal => InternalAccessor::new(start_guard.body_ref())?.child_for(key),
        };
        // Descend from the first child onward. Subsequent guards are owned.
        let mut page_id = next_page_id;
        loop {
            // Fresh-from-split leaves only live in `fresh_leaves` until
            // flush. If the next child is one, resolve from cache.
            if let Some(leaf) = self.fresh_leaves.get(&page_id) {
                return Self::value_from_cached_leaf(&self.pager, self.realm_id, leaf, key).await;
            }
            let (guard, kind) = self.read_node_guard(page_id).await?;
            match kind {
                NodeKind::Leaf => return self.extract_leaf_value(key, page_id, &guard).await,
                NodeKind::Internal => {
                    let next = InternalAccessor::new(guard.body_ref())?.child_for(key);
                    drop(guard);
                    page_id = next;
                }
            }
        }
    }

    async fn extract_leaf_value(
        &self,
        key: &[u8],
        leaf_page_id: u64,
        leaf_guard: &PageGuard,
    ) -> Result<Option<Vec<u8>>> {
        // Within a write txn, the dirty + fresh caches shadow the buffer-pool
        // bytes. The cached decoded form is the source of truth for any leaf
        // they hold.
        if let Some(leaf) = self
            .fresh_leaves
            .get(&leaf_page_id)
            .or_else(|| self.dirty_leaves.get(&leaf_page_id))
        {
            return match leaf.get(key) {
                None => Ok(None),
                Some(LeafValue::Inline(v)) => Ok(Some(v.clone())),
                Some(LeafValue::Overflow {
                    total_len,
                    root_page_id,
                }) => {
                    let v =
                        overflow::read_chain(&self.pager, self.realm_id, *root_page_id, *total_len)
                            .await?;
                    Ok(Some(v))
                }
            };
        }
        let leaf = LeafAccessor::new(leaf_guard.body_ref())?;
        let Some(idx) = leaf.find(key) else {
            return Ok(None);
        };
        match leaf.value_at(idx)? {
            LeafValueRef::Inline(v) => Ok(Some(v.to_vec())),
            LeafValueRef::Overflow {
                total_len,
                root_page_id,
            } => {
                let v = overflow::read_chain(&self.pager, self.realm_id, root_page_id, total_len)
                    .await?;
                Ok(Some(v))
            }
        }
    }

    /// Resolve a `LeafValue` to its raw bytes. Follows overflow chains as
    /// needed.
    pub(super) async fn resolve_leaf_value(&self, v: &LeafValue) -> Result<Vec<u8>> {
        match v {
            LeafValue::Inline(b) => Ok(b.clone()),
            LeafValue::Overflow {
                total_len,
                root_page_id,
            } => overflow::read_chain(&self.pager, self.realm_id, *root_page_id, *total_len).await,
        }
    }
}
