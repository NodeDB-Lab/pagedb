//! Persistent free-list operations.
//!
//! The free-list is stored in the catalog B+ tree as individual rows keyed
//! `[0x04] || page_id_be[8]`. The deferred-free queue is a single catalog row
//! `[0x05]` containing serialised `(commit_id, page_id)` pairs.
//!
//! These helpers are used both by [`WriteTxn::commit`] (to drain freed pages
//! into the deferred queue) and by [`compact_now`] (to promote eligible
//! deferred pages into the free-list and to allocate from it).

use std::sync::Arc;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CatalogRowKind};
use crate::pager::Pager;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

/// Pop the smallest `page_id` from the persistent free-list. Returns `None` if
/// the free-list is empty.
///
/// Modifies `cat_tree` in-place (deletes the chosen entry). The caller is
/// responsible for flushing `cat_tree` and committing the header afterward.
pub async fn alloc_page<V: Vfs + Clone>(cat_tree: &mut BTree<V>) -> Result<Option<u64>> {
    let start = vec![CatalogRowKind::FreeList as u8];
    let mut end = start.clone();
    end.push(0xFF);
    let rows = cat_tree.collect_range(&start, &end).await?;
    if let Some((key, _)) = rows.into_iter().next() {
        // Key layout: [0x04] || page_id_be[8] — 9 bytes total.
        if key.len() == 9 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&key[1..9]);
            let page_id = u64::from_be_bytes(b);
            cat_tree.delete(&key).await?;
            return Ok(Some(page_id));
        }
    }
    Ok(None)
}

/// Add `page_id` to the deferred-free queue tagged with `commit_id`. The page
/// becomes eligible for reuse once no tracked reader pins a `commit_id` ≤ this
/// `commit_id`.
///
/// Modifies `cat_tree` in-place. Caller flushes and commits.
pub async fn free_page_deferred<V: Vfs + Clone>(
    cat_tree: &mut BTree<V>,
    commit_id: u64,
    page_id: u64,
) -> Result<u64> {
    free_pages_deferred_batch(cat_tree, commit_id, &[page_id]).await
}

/// Batch-add multiple `page_id`s to the deferred-free queue in a single
/// catalog put. More efficient than calling `free_page_deferred` in a loop
/// when many pages need to be freed at once.
///
/// Modifies `cat_tree` in-place. Caller flushes and commits. Returns the
/// total pair count in the deferred-free row after the append; callers
/// (e.g. the stall-policy check) can use this to avoid re-reading the row.
pub async fn free_pages_deferred_batch<V: Vfs + Clone>(
    cat_tree: &mut BTree<V>,
    commit_id: u64,
    page_ids: &[u64],
) -> Result<u64> {
    if page_ids.is_empty() {
        return Ok(0);
    }
    let dk = Catalog::deferred_free_key();
    let mut pairs = match cat_tree.get(&dk).await? {
        Some(bytes) => Catalog::decode_deferred_free(&bytes)?,
        None => Vec::new(),
    };
    for &page_id in page_ids {
        pairs.push((commit_id, page_id));
    }
    // Keep sorted by commit_id for efficient draining.
    pairs.sort_unstable_by_key(|(cid, _)| *cid);
    let encoded = Catalog::encode_deferred_free(&pairs);
    cat_tree.put(&dk, &encoded).await?;
    Ok(pairs.len() as u64)
}

/// Drain all deferred-free entries with `commit_id < min_reader_commit` into
/// the persistent free-list. Returns the number of pages promoted.
///
/// Modifies `cat_tree` in-place. Caller flushes and commits.
pub async fn drain_deferred_to_freelist<V: Vfs + Clone>(
    cat_tree: &mut BTree<V>,
    min_reader_commit: u64,
) -> Result<u64> {
    let dk = Catalog::deferred_free_key();
    let pairs = match cat_tree.get(&dk).await? {
        Some(bytes) => Catalog::decode_deferred_free(&bytes)?,
        None => return Ok(0),
    };

    let (eligible, remaining): (Vec<_>, Vec<_>) = pairs
        .into_iter()
        .partition(|(cid, _)| *cid < min_reader_commit);

    let count = eligible.len() as u64;
    for (_cid, page_id) in eligible {
        let key = Catalog::free_list_key(page_id);
        cat_tree.put(&key, &[]).await?;
    }

    if remaining.is_empty() {
        let _ = cat_tree.delete(&dk).await?;
    } else {
        let encoded = Catalog::encode_deferred_free(&remaining);
        cat_tree.put(&dk, &encoded).await?;
    }

    Ok(count)
}

/// Persist the updated catalog state after free-list operations. This is a
/// low-level helper; callers that already hold the writer lock and have
/// modified a `BTree` should flush+commit themselves. Provided here for
/// completeness.
pub async fn persist_freelist_state<V: Vfs + Clone>(
    _pager: &Arc<Pager<V>>,
    _realm_id: RealmId,
) -> Result<()> {
    // Persistence is handled by the caller through the normal commit path.
    Ok(())
}
