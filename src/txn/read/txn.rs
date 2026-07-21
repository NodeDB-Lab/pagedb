use tokio::sync::OnceCell;

use crate::btree::BTree;
use crate::btree::node::NodeKind;
use crate::catalog::codec::{Catalog, SegmentMeta};
use crate::errors::PagedbError;
use crate::pager::PageGuard;
use crate::segment::reader::SegmentReader;
use crate::txn::db::Db;
use crate::vfs::Vfs;
use crate::{CommitId, RealmId, Result};

/// A snapshot-isolated read handle. Holds the `BTree` root and allocation
/// cursor at the time the transaction was opened. Unregisters automatically
/// on drop.
pub struct ReadTxn<'db, V: Vfs + Clone> {
    db: &'db Db<V>,
    commit_id: CommitId,
    root_page_id: u64,
    next_page_id: u64,
    catalog_root_page_id: u64,
    entry_id: u64,
    cached_root: OnceCell<(PageGuard, NodeKind)>,
    cached_catalog_root: OnceCell<(PageGuard, NodeKind)>,
}

impl<'db, V: Vfs + Clone> ReadTxn<'db, V> {
    pub(crate) fn new(
        db: &'db Db<V>,
        commit_id: CommitId,
        root_page_id: u64,
        next_page_id: u64,
        catalog_root_page_id: u64,
        entry_id: u64,
    ) -> Self {
        Self {
            db,
            commit_id,
            root_page_id,
            next_page_id,
            catalog_root_page_id,
            entry_id,
            cached_root: OnceCell::new(),
            cached_catalog_root: OnceCell::new(),
        }
    }

    #[must_use]
    pub fn commit_id(&self) -> CommitId {
        self.commit_id
    }

    #[must_use]
    pub fn next_page_id(&self) -> u64 {
        self.next_page_id
    }

    #[must_use]
    pub fn catalog_root_page_id(&self) -> u64 {
        self.catalog_root_page_id
    }

    #[must_use]
    pub fn root_page_id(&self) -> u64 {
        self.root_page_id
    }

    fn tree(&self) -> BTree<V> {
        BTree::open(
            self.db.pager.clone(),
            self.db.realm_id,
            self.root_page_id,
            self.next_page_id,
            self.db.page_size,
        )
    }

    fn catalog_tree(&self) -> BTree<V> {
        BTree::open(
            self.db.pager.clone(),
            self.db.realm_id,
            self.catalog_root_page_id,
            self.next_page_id,
            self.db.page_size,
        )
    }

    fn check_abort(&self) -> Result<()> {
        if self.db.take_reader_abort(self.entry_id) {
            return Err(PagedbError::Aborted);
        }
        Ok(())
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.check_abort()?;
        if self.root_page_id == 0 {
            return Ok(None);
        }
        let tree = self.tree();
        let (root_guard, root_kind) = self
            .cached_root
            .get_or_try_init(|| tree.read_node_guard(self.root_page_id))
            .await?;
        tree.get_with_cached_root(key, root_guard, *root_kind).await
    }

    pub async fn scan(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.check_abort()?;
        self.tree().collect_range(start, end).await
    }

    pub async fn scan_rev(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.check_abort()?;
        self.tree().scan_rev(start, end).await
    }

    pub async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.check_abort()?;
        self.tree().scan_prefix(prefix).await
    }

    pub async fn open_segment(&self, name: &str) -> Result<SegmentReader<V>> {
        self.check_abort()?;
        if self.catalog_root_page_id == 0 {
            return Err(PagedbError::NotFound);
        }
        let tree = self.catalog_tree();
        let key = Catalog::segment_key(self.db.realm_id, name.as_bytes())?;
        let (root_guard, root_kind) = self
            .cached_catalog_root
            .get_or_try_init(|| tree.read_node_guard(self.catalog_root_page_id))
            .await?;
        let value = tree
            .get_with_cached_root(&key, root_guard, *root_kind)
            .await?
            .ok_or(PagedbError::NotFound)?;
        let meta = Catalog::decode_segment_meta(&value)?;
        let limit = u64::try_from(self.db.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        SegmentReader::open_internal(
            self.db.pager.clone(),
            meta,
            self.db.mmap_bytes_in_use.clone(),
            limit,
        )
        .await
    }

    pub async fn list_segments(&self, prefix: &str) -> Result<Vec<SegmentMeta>> {
        self.check_abort()?;
        if self.catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = self.catalog_tree();
        let start = Catalog::segment_key(self.db.realm_id, prefix.as_bytes())?;
        let rows = tree.scan_prefix(&start).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            out.push(Catalog::decode_segment_meta(&v)?);
        }
        Ok(out)
    }

    #[must_use]
    pub fn realm_id(&self) -> RealmId {
        self.db.realm_id
    }
}

impl<V: Vfs + Clone> Drop for ReadTxn<'_, V> {
    fn drop(&mut self) {
        self.db.unregister_read(self.entry_id);
    }
}
