//! Validating the catalog's named-counter rows at open.

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::Catalog;
use crate::vfs::Vfs;

use crate::txn::db::core::Db;

/// Named-counter rows read per batch while validating them at open. Rows are a
/// fixed-width authenticated value, so this is a few KiB resident regardless of
/// how many counters the embedder has named.
const COUNTER_ROW_BATCH: usize = 512;

impl<V: Vfs + Clone> Db<V> {
    /// Authenticate and decode every persisted named-counter row during open.
    ///
    /// Named counters are already atomic with catalog-root publication, so
    /// recovery validates their encoding but never rewrites their values.
    ///
    /// Rows are streamed in bounded batches: how many counters an embedder has
    /// named is its business, and open must not size an allocation by it.
    pub(crate) async fn validate_counter_rows(
        &self,
        catalog_root_page_id: u64,
        next_page_id: u64,
    ) -> Result<()> {
        if catalog_root_page_id == 0 {
            return Ok(());
        }

        let prefix = [crate::catalog::codec::CatalogRowKind::Counter as u8];
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root_page_id,
            next_page_id,
            self.page_size,
        );
        let mut cursor: Vec<u8> = prefix.to_vec();
        loop {
            let batch = tree
                .collect_prefix_batch_from(&prefix, &cursor, COUNTER_ROW_BATCH)
                .await?;
            let Some((last_key, _)) = batch.last() else {
                return Ok(());
            };
            cursor.clear();
            cursor.extend_from_slice(last_key);
            // The exact successor of `last_key` in the key ordering: resume
            // strictly past the row just validated without re-reading it.
            cursor.push(0);
            let exhausted = batch.len() < COUNTER_ROW_BATCH;

            for (_key, value) in &batch {
                Catalog::decode_counter(value)?;
            }
            if exhausted {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::btree::BTree;
    use crate::catalog::codec::Catalog;
    use crate::vfs::memory::MemVfs;
    use crate::{Db, PagedbError, RealmId};

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0xA7; 16]);

    #[tokio::test(flavor = "current_thread")]
    async fn counter_recovery_surfaces_malformed_counter_row() {
        let db = Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, REALM)
            .await
            .unwrap();
        {
            let mut txn = db.begin_write().await.unwrap();
            let mut counter = txn.counter("bad-counter").unwrap();
            counter.set(5).await.unwrap();
            drop(counter);
            txn.commit().await.unwrap();
        }

        let (catalog_root, next_page_id) = {
            let state = db.writer.lock().await;
            (state.catalog_root_page_id, state.next_page_id)
        };
        let mut tree = BTree::open(
            db.pager.clone(),
            db.realm_id,
            catalog_root,
            next_page_id,
            db.page_size,
        );
        tree.put(&Catalog::counter_key(&[0xFF]).unwrap(), b"bad")
            .await
            .unwrap();
        tree.flush().await.unwrap();

        let err = db
            .validate_counter_rows(tree.root_page_id(), tree.next_page_id())
            .await
            .expect_err("malformed counter row must surface during recovery validation");
        assert!(matches!(err, PagedbError::Corruption(_)));
    }
}
