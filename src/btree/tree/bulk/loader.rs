//! Push-style dense-tree builder.
//!
//! Records are handed in one at a time, in strictly increasing key order, and
//! leaves plus internal nodes are emitted as the input flows past. Nothing
//! accumulates that scales with the number of records, so a caller that reads
//! its source in bounded batches never materialises the source at all.

use bytes::Bytes;

use crate::Result;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

use crate::btree::leaf::{Leaf, LeafValue};
use crate::btree::node;
use crate::btree::overflow;
use crate::btree::tree::core::BTree;

use super::levels::{Child, LevelAccum};

mod batch;

/// Bytes one record adds to a leaf body: the slot-directory entry, the
/// key-suffix length field, the key itself, and the encoded value.
///
/// Mirrors `Leaf::single_record_fits_encoded`, which sizes the same record
/// against an empty leaf; the two must agree or a leaf would be packed past
/// what the encoder can lay out.
fn leaf_record_cost(key_len: usize, value: &LeafValue) -> Result<usize> {
    2usize
        .checked_add(2)
        .and_then(|size| size.checked_add(key_len))
        .and_then(|size| size.checked_add(value.encoded_size()))
        .ok_or(PagedbError::PayloadTooLarge)
}

/// Builds a dense B+ tree from records pushed in ascending key order.
///
/// Resident cost is one leaf under construction plus one partially-filled
/// internal node per level — `O(height × page_size)` — however many records pass
/// through. That is what lets a dense repack of a store far larger than the
/// buffer-pool budget run inside that budget.
///
/// Value resolution spills past the inline threshold to overflow chains and is
/// therefore `async`, which is why records are pushed in rather than pulled from
/// an iterator.
pub struct BulkLoader<'a, V: Vfs> {
    tree: &'a mut BTree<V>,
    body_cap: usize,
    inline_threshold: usize,
    /// Last key pushed. Carrying it is the whole of the strictly-increasing
    /// check: pairwise comparison against it spans batch boundaries exactly as
    /// it spans records inside one batch.
    last_key: Option<Vec<u8>>,
    /// Records of the leaf under construction, and the body bytes they occupy.
    leaf_records: Vec<(Vec<u8>, LeafValue)>,
    leaf_used: usize,
    /// Page id already reserved for the leaf under construction. Taken when the
    /// previous leaf was written so that leaf's right-sibling link could name
    /// it: ids are drawn from the same allocator overflow chains use, so the
    /// next leaf's id cannot be predicted and must exist before the current one
    /// is encoded. Never more than one leaf ahead.
    leaf_page_id: Option<u64>,
    /// Page id of the last leaf written, for the next leaf's left-sibling link.
    left_sibling: u64,
    leaf_count: u64,
    /// Page id of the first leaf written; the root when it is also the only one.
    first_leaf_page_id: u64,
    levels: Vec<LevelAccum>,
    alternate_flush_path: Option<String>,
}

impl<'a, V: Vfs> BulkLoader<'a, V> {
    pub(crate) fn new(tree: &'a mut BTree<V>, alternate_flush_path: Option<String>) -> Self {
        let body_cap = node::body_capacity(tree.page_size);
        let inline_threshold = overflow::inline_value_threshold(tree.page_size);
        Self {
            tree,
            body_cap,
            inline_threshold,
            last_key: None,
            leaf_records: Vec::new(),
            leaf_used: node::HEADER_LEN,
            leaf_page_id: None,
            left_sibling: 0,
            leaf_count: 0,
            first_leaf_page_id: 0,
            levels: Vec::new(),
            alternate_flush_path,
        }
    }

    /// Append one record. Keys must arrive strictly increasing.
    ///
    /// This is the one-record form of [`Self::push_batch`], preserving the
    /// existing streaming API and its ordering/error semantics.
    pub async fn push(&mut self, key: Vec<u8>, value: Bytes) -> Result<()> {
        self.push_batch(vec![(key, value)]).await
    }

    /// Append a bounded ordered batch.
    ///
    /// The complete batch is checked for strict ordering and exact leaf and
    /// separator fit before it can allocate a page, write overflow storage, or
    /// alter the in-progress leaf. Inline records then flow through a tight
    /// synchronous loop; async dirty-budget checks happen only at the batch
    /// boundary or when page emission itself requires an await.
    pub async fn push_batch(&mut self, batch: Vec<(Vec<u8>, Bytes)>) -> Result<()> {
        batch::push_batch(self, batch).await
    }

    /// Write the last leaf, close every internal level, and publish the root on
    /// the tree. An empty input leaves the tree empty.
    pub async fn finish(mut self) -> Result<()> {
        if !self.leaf_records.is_empty() {
            self.close_leaf(false).await?;
        }
        if self.leaf_count == 0 {
            return Ok(());
        }
        if self.leaf_count == 1 {
            self.tree.root_page_id = self.first_leaf_page_id;
            return Ok(());
        }

        let mut level = 0usize;
        while level < self.levels.len() {
            // A level that only ever saw one child is already the top of the
            // tree; a node wrapping it would route nowhere.
            if let Some(page_id) = self.levels[level].sole_child() {
                self.tree.root_page_id = page_id;
                return Ok(());
            }
            let Some((node, separator)) = self.levels[level].take_node() else {
                break;
            };
            let page_id = self.tree.allocate_page();
            self.tree.write_internal(page_id, &node).await?;
            self.flush_if_dirty_budget().await?;
            self.push_child(level + 1, (page_id, separator)).await?;
            level += 1;
        }
        // Every level either resolves to the root or feeds the level above it,
        // so the walk above always returns. Reaching here would mean a level
        // vanished mid-build.
        Err(PagedbError::Io(std::io::Error::other(
            "bulk load: internal levels ended without a root",
        )))
    }

    /// Write the leaf under construction and hand its `(page_id, first key)` to
    /// the level above.
    ///
    /// When more records follow, the next leaf's page id is reserved *before*
    /// this leaf is encoded, because this leaf's right-sibling link has to name
    /// it and ids are not predictable — an overflow chain written for the next
    /// record draws from the same allocator. Two leaves' worth of state is the
    /// most this ever holds.
    async fn close_leaf(&mut self, more_records: bool) -> Result<()> {
        let page_id = match self.leaf_page_id.take() {
            Some(reserved) => reserved,
            None => self.tree.allocate_page(),
        };
        let right_sibling = if more_records {
            let next = self.tree.allocate_page();
            self.leaf_page_id = Some(next);
            next
        } else {
            0
        };
        let records = std::mem::take(&mut self.leaf_records);
        let first_key = records
            .first()
            .map(|(key, _)| key.clone())
            .unwrap_or_default();
        let leaf = Leaf {
            left_sibling: self.left_sibling,
            right_sibling,
            records,
        };
        self.tree.write_leaf(page_id, &leaf).await?;
        self.flush_if_dirty_budget().await?;
        self.left_sibling = page_id;
        self.leaf_used = node::HEADER_LEN;
        if self.leaf_count == 0 {
            self.first_leaf_page_id = page_id;
        }
        self.leaf_count += 1;
        self.push_child(0, (page_id, first_key)).await
    }

    /// Offer `child` to internal level `level`, cascading upward: a level that
    /// fills up emits its node, which becomes a child of the level above, which
    /// may itself fill up. At most one node per level is ever resident.
    async fn push_child(&mut self, mut level: usize, mut child: Child) -> Result<()> {
        let body_cap = self.body_cap;
        loop {
            while self.levels.len() <= level {
                self.levels.push(LevelAccum::new());
            }
            let (node, separator) = {
                let accum = &mut self.levels[level];
                if accum.try_push(&child, body_cap)? {
                    return Ok(());
                }
                // `try_push` only reports full for a node that already holds
                // more than one child, so a node is always there to take.
                // Returning without one would drop a whole subtree.
                let Some(full) = accum.take_node() else {
                    return Err(PagedbError::Io(std::io::Error::other(
                        "bulk load: a full internal level held no node",
                    )));
                };
                accum.restart(child);
                full
            };
            let page_id = self.tree.allocate_page();
            self.tree.write_internal(page_id, &node).await?;
            self.flush_if_dirty_budget().await?;
            child = (page_id, separator);
            level += 1;
        }
    }

    async fn flush_if_dirty_budget(&self) -> Result<()> {
        if self.tree.pager.main_dirty_at_budget() {
            match self.alternate_flush_path.as_deref() {
                Some(path) => {
                    self.tree
                        .pager
                        .flush_main_to(self.tree.realm_id, path)
                        .await?
                }
                None => self.tree.pager.flush_main(self.tree.realm_id).await?,
            }
        }
        Ok(())
    }
}

impl<V: Vfs> BTree<V> {
    /// Start a streaming bulk load into this (empty) tree.
    ///
    /// The returned loader packs records into leaves and builds internal nodes
    /// bottom-up as they arrive, writing each page exactly once. Callers holding
    /// the whole input already can use [`Self::bulk_load`] instead.
    ///
    /// Returns `Err` if the tree is not empty.
    pub fn bulk_loader(&mut self) -> Result<BulkLoader<'_, V>> {
        if self.root_page_id != 0 {
            return Err(PagedbError::Io(std::io::Error::other(
                "bulk_load: tree must be empty",
            )));
        }
        Ok(BulkLoader::new(self, None))
    }

    pub(crate) fn bulk_loader_to(&mut self, path: &str) -> Result<BulkLoader<'_, V>> {
        if self.root_page_id != 0 {
            return Err(PagedbError::Io(std::io::Error::other(
                "bulk_load: tree must be empty",
            )));
        }
        Ok(BulkLoader::new(self, Some(path.to_string())))
    }

    /// Bulk-load sorted `(key, value)` pairs into a freshly-created tree
    /// without any `CoW` overhead. The tree must be empty (`root_page_id == 0`).
    ///
    /// Convenience wrapper over [`Self::bulk_loader`] for callers that already
    /// hold their whole input; the contract is the loader's — strictly
    /// increasing keys, values past the inline threshold spilled to overflow
    /// chains, each page written exactly once.
    ///
    /// Returns `Err` if the tree is not empty.
    ///
    /// The repack streams through [`Self::bulk_loader`] instead, so the only
    /// caller holding a whole input is the incremental-apply history carry,
    /// which is native-only.
    #[cfg(any(test, not(target_arch = "wasm32")))]
    pub async fn bulk_load(&mut self, pairs: Vec<(Vec<u8>, Bytes)>) -> Result<()> {
        let mut loader = self.bulk_loader()?;
        for (key, value) in pairs {
            loader.push(key, value).await?;
        }
        loader.finish().await
    }
}
