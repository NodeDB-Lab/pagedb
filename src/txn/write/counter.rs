//! `CounterRef` — durable monotonic named counters scoped to a `WriteTxn`.

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::Catalog;
use crate::errors::PagedbError;
use crate::vfs::Vfs;

/// A handle to a named durable monotonic counter, scoped to a `WriteTxn`.
///
/// The counter starts at `0` if it has never been written. Values are stored
/// as 8-byte little-endian `u64` catalog rows with key prefix `0x02`.
///
/// Monotonicity guarantee: `set(v)` returns `PagedbError::Aborted` when
/// `v < current`; `increment_by` can never produce a value smaller than the
/// current one. Values only survive once the enclosing `WriteTxn::commit`
/// succeeds.
pub struct CounterRef<'a, V: Vfs + Clone> {
    pub(super) catalog_tree: &'a mut BTree<V>,
    pub(super) main_tree: &'a mut BTree<V>,
    pub(super) key: Vec<u8>,
}

impl<V: Vfs + Clone> CounterRef<'_, V> {
    /// Return the current counter value, or `0` if no row exists yet.
    pub async fn get(&self) -> Result<u64> {
        match self.catalog_tree.get(&self.key).await? {
            Some(v) => Catalog::decode_counter(&v),
            None => Ok(0),
        }
    }

    /// Set the counter to `value`. Returns `PagedbError::Aborted` when
    /// `value < current` (strict monotonicity).
    pub async fn set(&mut self, value: u64) -> Result<()> {
        let current = self.get().await?;
        if value < current {
            return Err(PagedbError::Aborted);
        }
        Self::sync_to(self.main_tree, self.catalog_tree);
        let bytes = Catalog::encode_counter(value);
        self.catalog_tree.put(&self.key, &bytes).await?;
        Self::sync_from(self.catalog_tree, self.main_tree);
        Ok(())
    }

    /// Increment the counter by `delta` and return the new value. Returns
    /// `PagedbError::NonceCounterExhausted` on `u64` overflow.
    pub async fn increment_by(&mut self, delta: u64) -> Result<u64> {
        let current = self.get().await?;
        let next = current
            .checked_add(delta)
            .ok_or(PagedbError::NonceCounterExhausted)?;
        Self::sync_to(self.main_tree, self.catalog_tree);
        let bytes = Catalog::encode_counter(next);
        self.catalog_tree.put(&self.key, &bytes).await?;
        Self::sync_from(self.catalog_tree, self.main_tree);
        Ok(next)
    }

    /// Advance the catalog allocator cursor to be at least as high as the
    /// main tree's before a catalog write.
    fn sync_to(main: &BTree<V>, catalog: &mut BTree<V>) {
        let shared = main.next_page_id().max(catalog.next_page_id());
        catalog.set_next_page_id(shared);
    }

    /// After a catalog write, propagate any advances back to the main tree.
    fn sync_from(catalog: &BTree<V>, main: &mut BTree<V>) {
        let c = catalog.next_page_id();
        if main.next_page_id() < c {
            main.set_next_page_id(c);
        }
    }
}
