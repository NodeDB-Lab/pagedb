//! Bounded-batch admission and append path for [`super::BulkLoader`].
//!
//! Admission intentionally happens for the entire batch before any overflow
//! chain, leaf, or internal page is written. That makes a malformed batch a
//! no-op while keeping the hot inline path free of per-record async budget
//! checks.

use std::sync::Arc;

use bytes::Bytes;

use crate::Result;
use crate::btree::leaf::LeafValue;
use crate::btree::overflow;
use crate::errors::PagedbError;

use super::{BulkLoader, leaf_record_cost};

pub(super) async fn push_batch<V: crate::vfs::Vfs>(
    loader: &mut BulkLoader<'_, V>,
    batch: Vec<(Vec<u8>, Bytes)>,
) -> Result<()> {
    prevalidate(loader, &batch)?;
    let Some((last_key, _)) = batch.last() else {
        return Ok(());
    };
    // The leaf owns every input key, so retain only the final batch boundary
    // for the next batch's monotonicity check rather than cloning each record.
    let batch_boundary = last_key.clone();

    for (key, value) in batch {
        let stored = if value.len() > loader.inline_threshold {
            let total_len = value.len() as u64;
            let pager = Arc::clone(&loader.tree.pager);
            let realm_id = loader.tree.realm_id;
            let page_size = loader.tree.page_size;
            let tree = &mut *loader.tree;
            let flush_target = match loader.alternate_flush_path.as_deref() {
                Some(path) => overflow::OverflowFlushTarget::Alternate(path),
                None => overflow::OverflowFlushTarget::Main,
            };
            let root_page_id = overflow::write_chain(
                &pager,
                realm_id,
                &value,
                page_size,
                &mut || tree.allocate_page(),
                flush_target,
            )
            .await?;
            LeafValue::Overflow {
                total_len,
                root_page_id,
            }
        } else {
            LeafValue::Inline(value)
        };

        let cost = leaf_record_cost(key.len(), &stored)?;
        let projected = projected_encoded_size(loader, &key, cost)?;
        if projected > loader.body_cap && !loader.leaf_records.is_empty() {
            loader.close_leaf(true).await?;
        }
        // `leaf_used` tracks the uncompressed representation. The fit check
        // subtracts the exact shared-prefix saving using the first and newest
        // sorted keys, which bracket every key already in this leaf.
        loader.leaf_used = loader
            .leaf_used
            .checked_add(cost)
            .ok_or(PagedbError::PayloadTooLarge)?;
        loader.leaf_records.push((key, stored));
    }

    loader.last_key = Some(batch_boundary);
    // A batch boundary is the only dirty-budget check for inline records.
    loader.flush_if_dirty_budget().await
}

fn projected_encoded_size<V: crate::vfs::Vfs>(
    loader: &BulkLoader<'_, V>,
    key: &[u8],
    cost: usize,
) -> Result<usize> {
    let uncompressed = loader
        .leaf_used
        .checked_add(cost)
        .ok_or(PagedbError::PayloadTooLarge)?;
    let Some((first_key, _)) = loader.leaf_records.first() else {
        return Ok(uncompressed);
    };
    let prefix_len = first_key
        .iter()
        .zip(key)
        .take_while(|(left, right)| left == right)
        .count();
    let shared_prefix_saving = loader
        .leaf_records
        .len()
        .checked_mul(prefix_len)
        .ok_or(PagedbError::PayloadTooLarge)?;
    uncompressed
        .checked_sub(shared_prefix_saving)
        .ok_or(PagedbError::PayloadTooLarge)
}

fn prevalidate<V: crate::vfs::Vfs>(
    loader: &BulkLoader<'_, V>,
    batch: &[(Vec<u8>, Bytes)],
) -> Result<()> {
    validate_order(loader.last_key.as_deref(), batch)?;
    for (key, value) in batch {
        loader.tree.validate_insert_record_fits(key, value)?;
    }
    Ok(())
}

fn validate_order(previous: Option<&[u8]>, batch: &[(Vec<u8>, Bytes)]) -> Result<()> {
    let mut prior = previous;
    for (key, _) in batch {
        if prior.is_some_and(|last| key.as_slice() <= last) {
            return Err(PagedbError::BulkLoadNotMonotonic);
        }
        prior = Some(key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;

    use super::BulkLoader;
    use crate::RealmId;
    use crate::btree::BTree;
    use crate::btree::node::body_capacity;
    use crate::crypto::CipherId;
    use crate::crypto::kdf::derive_mk;
    use crate::errors::PagedbError;
    use crate::pager::{Pager, PagerConfig};
    use crate::vfs::memory::MemVfs;

    const PAGE: usize = 4096;

    async fn fresh_tree() -> BTree<MemVfs> {
        let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let config = PagerConfig {
            page_size: PAGE,
            buffer_pool_pages: 64,
            segment_cache_pages: 64,
            cipher_id: CipherId::Aes256Gcm,
            mk_epoch: 0,
            main_db_file_id: [0xAB; 16],
            main_db_path: "/main.db".into(),
            anchor_budget: 1_000_000,
            dek_lru_capacity: 16,
            observer_retry_count: 0,
            metrics_enabled: true,
        };
        let pager = Arc::new(Pager::open(MemVfs::new(), mk, config).await.unwrap());
        BTree::open(pager, RealmId::new([1; 16]), 0, 4, PAGE)
    }

    fn record(key: &[u8]) -> (Vec<u8>, Bytes) {
        (key.to_vec(), Bytes::from_static(b"value"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejected_batch_prevalidation_leaves_tree_unallocated_and_empty() {
        let oversized_key = vec![b'z'; body_capacity(PAGE) - 32];
        let rejected_batches = vec![
            vec![record(b"a"), record(b"a")],
            vec![record(b"b"), record(b"a")],
            vec![(b"a".to_vec(), Bytes::new()), (oversized_key, Bytes::new())],
        ];

        for batch in rejected_batches {
            let mut tree = fresh_tree().await;
            let initial_next_page = tree.next_page_id();
            let error = {
                let mut loader = BulkLoader::new(&mut tree, None);
                loader.push_batch(batch).await.unwrap_err()
            };
            assert!(matches!(
                error,
                PagedbError::BulkLoadNotMonotonic | PagedbError::PayloadTooLarge
            ));
            assert_eq!(
                tree.root_page_id(),
                0,
                "rejected batch must not publish a root"
            );
            assert_eq!(
                tree.next_page_id(),
                initial_next_page,
                "rejected batch must not allocate"
            );

            {
                let mut loader = BulkLoader::new(&mut tree, None);
                loader.push_batch(vec![record(b"z")]).await.unwrap();
                loader.finish().await.unwrap();
            }
            assert!(tree.get(b"a").await.unwrap().is_none());
            assert_eq!(
                tree.get(b"z").await.unwrap().as_deref(),
                Some(b"value".as_ref())
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejected_later_batch_preserves_accepted_boundary_and_leaf() {
        let mut tree = fresh_tree().await;
        {
            let mut loader = BulkLoader::new(&mut tree, None);
            loader
                .push_batch(vec![record(b"a"), record(b"b")])
                .await
                .unwrap();
            let leaf_count = loader.leaf_records.len();
            let error = loader
                .push_batch(vec![record(b"c"), record(b"c")])
                .await
                .unwrap_err();
            assert!(matches!(error, PagedbError::BulkLoadNotMonotonic));
            assert_eq!(loader.last_key.as_deref(), Some(b"b".as_slice()));
            assert_eq!(loader.leaf_records.len(), leaf_count);

            loader.push_batch(vec![record(b"c")]).await.unwrap();
            loader.finish().await.unwrap();
        }

        for key in [b"a".as_slice(), b"b", b"c"] {
            assert_eq!(
                tree.get(key).await.unwrap().as_deref(),
                Some(b"value".as_ref())
            );
        }
    }
}
