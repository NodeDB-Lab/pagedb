//! Internal helpers shared by `compact_now` and `compact_step`: range
//! collection, catalog splitting, segment housekeeping, and header construction.

use std::sync::Arc;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CatalogRowKind, CompactionStateRow, SegmentMeta};
use crate::errors::PagedbError;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::txn::db::{Db, WriterState};
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

/// Collect catalog pairs split into two groups:
/// - `non_housekeeping`: all rows that are NOT free-list or deferred-free rows.
/// - `deferred_pairs`: the decoded deferred-free queue entries.
///
/// Free-list rows are intentionally excluded; they will be reconstructed
/// during compaction by promoting eligible deferred-free entries.
pub(super) async fn collect_catalog_split<V: Vfs + Clone>(
    pager: &Arc<crate::pager::Pager<V>>,
    realm_id: crate::RealmId,
    state: &WriterState,
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Vec<(u64, u64)>)> {
    if state.catalog_root_page_id == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    let tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        pager.page_size(),
    );
    let all = collect_all_pairs(&tree).await?;

    let fl_byte = CatalogRowKind::FreeList as u8;
    let df_key = Catalog::deferred_free_key();

    let mut non_housekeeping: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut deferred_pairs: Vec<(u64, u64)> = Vec::new();

    for (k, v) in all {
        if k.first() == Some(&fl_byte) {
            // Free-list row — drop; will be rebuilt from eligible deferred entries.
            continue;
        }
        if k == df_key {
            // Deferred-free row — decode separately.
            deferred_pairs = Catalog::decode_deferred_free(&v)?;
            continue;
        }
        non_housekeeping.push((k, v));
    }

    Ok((non_housekeeping, deferred_pairs))
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
    db.pager.commit_anchor(counter_anchor)?;

    // Promote staging file to live.
    db.vfs.mkdir_all("seg").await?;
    let staging = crate::segment::writer::staging_path(&new_meta.segment_id);
    let live = crate::segment::writer::live_path(&new_meta.segment_id);
    db.vfs.rename(&staging, &live).await?;
    db.vfs.sync_dir("seg").await.ok();

    // Tombstone old segment.
    let old_live = crate::segment::writer::live_path(old_segment_id);
    let tomb = format!(
        "seg/.tombstone/{}.{}",
        crate::hex::to_hex_lower(old_segment_id),
        new_commit_id,
    );
    db.vfs.mkdir_all("seg/.tombstone").await?;
    db.vfs.rename(&old_live, &tomb).await.ok();
    db.vfs.sync_dir("seg/.tombstone").await.ok();

    state.catalog_root_page_id = new_cat_root;
    state.next_page_id = new_next;
    state.active_slot = new_slot;
    state.seq = new_seq;
    state.latest_commit_id = new_commit_id;
    db.latest_commit
        .store(new_commit_id, std::sync::atomic::Ordering::SeqCst);

    Ok(())
}

/// Return the "next key strictly greater than `key`" for range scanning.
/// Appends a 0x00 byte, which gives the lexicographically smallest key
/// greater than `key`. If `key` is empty, returns empty (scan from start).
pub(super) fn next_key_after(key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        Vec::new()
    } else {
        let mut v = key.to_vec();
        v.push(0x00);
        v
    }
}

/// Collect at most `limit` key-value pairs from `[start..end)` in `tree`.
pub(super) async fn collect_range_limited<V: Vfs + Clone>(
    tree: &BTree<V>,
    start: &[u8],
    end: &[u8],
    limit: u64,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut pairs = tree.collect_range(start, end).await?;
    #[allow(clippy::cast_possible_truncation)]
    if pairs.len() as u64 > limit {
        pairs.truncate(limit as usize);
    }
    Ok(pairs)
}

/// Load the compaction watermark from the catalog, if present.
pub(super) async fn load_compaction_state<V: Vfs + Clone>(
    pager: &Arc<crate::pager::Pager<V>>,
    realm_id: crate::RealmId,
    state: &WriterState,
) -> Result<Option<CompactionStateRow>> {
    if state.catalog_root_page_id == 0 {
        return Ok(None);
    }
    let tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        pager.page_size(),
    );
    let key = Catalog::compaction_state_key();
    match tree.get(&key).await? {
        Some(bytes) => {
            let cs = Catalog::decode_compaction_state(&bytes)?;
            Ok(Some(cs))
        }
        None => Ok(None),
    }
}

/// Load just the `frontier_page_id` from the watermark (for progress reporting).
pub(super) async fn load_frontier_page_id<V: Vfs + Clone>(
    pager: &Arc<crate::pager::Pager<V>>,
    realm_id: crate::RealmId,
    state: &WriterState,
) -> Option<u64> {
    match load_compaction_state(pager, realm_id, state).await {
        Ok(Some(cs)) => Some(cs.frontier_page_id),
        _ => None,
    }
}

/// Build [`MainDbHeaderFields`] for a commit.
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
) -> MainDbHeaderFields {
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
        free_list_root: [0u8; 16],
        catalog_root: catalog_root_bytes,
        apply_journal_root_page_id: 0,
        apply_journal_root_version: 0,
        commit_history_root_page_id: state.commit_history_root_page_id,
        commit_history_root_version: state.commit_history_root_version,
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
