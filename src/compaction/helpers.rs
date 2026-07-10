//! Internal helpers shared by `compact_now` and `compact_step`: range
//! collection, catalog splitting, segment housekeeping, and header construction.

use std::sync::Arc;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CatalogRowKind, SegmentMeta};
use crate::errors::PagedbError;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::txn::db::{Db, WriterState};
use crate::txn::write::SegmentSideEffect;
use crate::vfs::Vfs;
use crate::{CommitId, Result};

/// Collect ALL key-value pairs from a tree via full leaf-level scan.
/// Uses an empty start and a sentinel beyond any possible key.
pub(super) async fn collect_all_pairs<V: Vfs + Clone>(
    tree: &BTree<V>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    // [0xFF; 256] is beyond any realistic key in this codebase.
    tree.collect_range(&[], &[0xFF; 256]).await
}

/// Collect every catalog row, for rebuilding the catalog tree during a dense
/// repack. Free pages are tracked in the durable free-list chain (reset
/// separately by the repack), not in the catalog, so there are no housekeeping
/// rows to filter here.
pub(super) async fn collect_catalog_split<V: Vfs + Clone>(
    pager: &Arc<crate::pager::Pager<V>>,
    realm_id: crate::RealmId,
    state: &WriterState,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if state.catalog_root_page_id == 0 {
        return Ok(Vec::new());
    }
    let tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        pager.page_size(),
    );
    collect_all_pairs(&tree).await
}

pub(super) async fn list_all_segments_inner<V: Vfs + Clone>(
    pager: &Arc<crate::pager::Pager<V>>,
    realm_id: crate::RealmId,
    state: &WriterState,
) -> Result<Vec<SegmentMeta>> {
    if state.catalog_root_page_id == 0 {
        return Ok(Vec::new());
    }
    let tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        pager.page_size(),
    );
    let start = vec![CatalogRowKind::Segment as u8];
    let mut end = start.clone();
    end.push(0xFF);
    let rows = tree.collect_range(&start, &end).await?;
    let mut out = Vec::with_capacity(rows.len());
    for (_k, v) in rows {
        let meta = Catalog::decode_segment_meta(&v)?;
        out.push(meta);
    }
    Ok(out)
}

pub(super) async fn find_segment_name_inner<V: Vfs + Clone>(
    pager: &Arc<crate::pager::Pager<V>>,
    realm_id: crate::RealmId,
    state: &WriterState,
    segment_id: &[u8; 16],
) -> Result<String> {
    if state.catalog_root_page_id == 0 {
        return Err(PagedbError::NotFound);
    }
    let tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        pager.page_size(),
    );
    let start = vec![CatalogRowKind::Segment as u8];
    let mut end = start.clone();
    end.push(0xFF);
    let rows = tree.collect_range(&start, &end).await?;
    for (k, v) in rows {
        let meta = Catalog::decode_segment_meta(&v)?;
        if meta.segment_id == *segment_id && k.len() > 17 {
            return Ok(String::from_utf8_lossy(&k[17..]).into_owned());
        }
    }
    Err(PagedbError::NotFound)
}

pub(super) async fn replace_segment_compact<V: Vfs + Clone>(
    db: &Db<V>,
    state: &mut WriterState,
    visibility: &tokio::sync::RwLockWriteGuard<'_, ()>,
    name: &str,
    old_segment_id: &[u8; 16],
    new_meta: &SegmentMeta,
) -> Result<()> {
    let key = Catalog::segment_key(db.realm_id, name.as_bytes())?;
    let value = Catalog::encode_segment_meta(new_meta);

    let mut cat_tree = BTree::open(
        db.pager.clone(),
        db.realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        db.page_size,
    );
    cat_tree.put(&key, &value).await?;
    cat_tree.flush().await?;

    let new_cat_root = cat_tree.root_page_id();
    let new_next = cat_tree.next_page_id().max(state.next_page_id);
    let new_commit_id = state.latest_commit_id + 1;
    let new_seq = state.seq + 1;
    let counter_anchor = db.pager.pending_anchor();

    let mut catalog_root_bytes = [0u8; 16];
    catalog_root_bytes[..8].copy_from_slice(&new_cat_root.to_le_bytes());
    catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());

    let fields = MainDbHeaderFields {
        format_version: 1,
        cipher_id: db.cipher_id.as_byte(),
        page_size_log2: page_size_log2(db.page_size)?,
        flags: 0,
        file_id: db.file_id,
        kek_salt: db.kek_salt,
        mk_epoch: db.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
        seq: new_seq,
        active_root_page_id: state.root_page_id,
        active_root_txn_id: state.latest_commit_id,
        counter_anchor,
        commit_id: CommitId(new_commit_id),
        free_list_root: [0u8; 16],
        catalog_root: catalog_root_bytes,
        apply_journal_root_page_id: 0,
        apply_journal_root_version: 0,
        commit_history_root_page_id: 0,
        commit_history_root_version: 0,
        restore_mode: 0,
        next_page_id: new_next,
        commit_retain_policy_tag: 0,
        commit_retain_policy_value: 0,
    };

    let hk_clone = { db.hk.read().clone() };
    let new_slot = commit_header(
        &*db.vfs,
        &db.main_db_path,
        &hk_clone,
        &fields,
        state.active_slot,
        db.page_size,
    )
    .await?;
    // The catalog is durable at this point. Preserve its state internally but
    // retain the prior reader snapshot until segment replacement is reconciled.
    state.catalog_root_page_id = new_cat_root;
    state.catalog_root_txn_id = new_commit_id;
    state.next_page_id = new_next;
    state.active_slot = new_slot;
    state.seq = new_seq;
    state.latest_commit_id = new_commit_id;

    let effects = [
        SegmentSideEffect::Tombstone {
            segment_id: *old_segment_id,
            tombstone_commit_id: None,
        },
        SegmentSideEffect::Promote {
            segment_id: new_meta.segment_id,
        },
    ];
    let _ = db
        .finish_durable_commit_visible(
            visibility,
            state,
            CommitId(new_commit_id),
            counter_anchor,
            &effects,
        )
        .await?;
    Ok(())
}

/// Build [`MainDbHeaderFields`] for a compaction commit.
///
/// Compaction relocates/truncates pages, so it discards the commit-history
/// index (`commit_history_root = 0`) — exactly as `compact_now` does. Writing
/// the *old* history root here would leave the durable header pointing at a
/// history tree the repack just overwrote/truncated, so a later `begin_read_at`
/// would read garbage. `free_list_root` is supplied by the caller: an
/// intermediate step preserves the still-valid chain; the final dense repack
/// passes 0 (the relocated layout starts with an empty free-list).
#[allow(clippy::too_many_arguments)]
pub(super) fn make_header_fields<V: Vfs + Clone>(
    db: &Db<V>,
    state: &WriterState,
    new_commit_id: u64,
    new_seq: u64,
    counter_anchor: u64,
    new_root: u64,
    new_cat_root: u64,
    new_next: u64,
    free_list_root_page_id: u64,
) -> MainDbHeaderFields {
    let _ = state;
    let mut catalog_root_bytes = [0u8; 16];
    catalog_root_bytes[..8].copy_from_slice(&new_cat_root.to_le_bytes());
    catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());
    MainDbHeaderFields {
        format_version: 1,
        cipher_id: db.cipher_id.as_byte(),
        page_size_log2: page_size_log2(db.page_size).unwrap_or(12),
        flags: 0,
        file_id: db.file_id,
        kek_salt: db.kek_salt,
        mk_epoch: db.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
        seq: new_seq,
        active_root_page_id: new_root,
        active_root_txn_id: new_commit_id,
        counter_anchor,
        commit_id: CommitId(new_commit_id),
        free_list_root: crate::txn::db::encode_free_list_root(free_list_root_page_id),
        catalog_root: catalog_root_bytes,
        apply_journal_root_page_id: 0,
        apply_journal_root_version: 0,
        commit_history_root_page_id: 0,
        commit_history_root_version: 0,
        restore_mode: 0,
        next_page_id: new_next,
        commit_retain_policy_tag: 0,
        commit_retain_policy_value: 0,
    }
}

pub(super) fn page_size_log2(page_size: usize) -> Result<u8> {
    match page_size {
        4096 => Ok(12),
        8192 => Ok(13),
        16384 => Ok(14),
        32768 => Ok(15),
        65536 => Ok(16),
        _ => Err(PagedbError::Unsupported),
    }
}
