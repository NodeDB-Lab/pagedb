//! Internal helpers shared by `compact_now` and `compact_step`: streaming tree
//! rebuild, catalog row paging, segment housekeeping, and header construction.

use std::sync::Arc;

use bytes::Bytes;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CatalogRowKind, SegmentMeta};
use crate::errors::PagedbError;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::txn::db::{Db, WriterState};
use crate::txn::write::SegmentSideEffect;
use crate::vfs::Vfs;
use crate::{CommitId, Result};

/// Records read from the source tree per batch while a repack streams it.
///
/// One batch is the whole of what the repack holds of the source; the compacted
/// side holds one leaf plus one internal node per level. Neither scales with the
/// size of the store.
const REPACK_RECORD_BATCH: usize = 256;

/// Rebuild every record of the tree rooted at `source_root` into `dest` as a
/// dense tree, streaming the source in bounded batches.
///
/// `keep` selects which rows carry over; rejected rows are dropped from the
/// compacted tree.
///
/// The source is walked with no upper key bound — it is read to the end and cut
/// off at the batch limit — because keys are arbitrary byte strings with no
/// reserved sentinel and no length ceiling: a scan bounded by any invented
/// maximum would drop the records at the top of the keyspace and publish a
/// truncated-but-internally-consistent tree, which is silent durable data loss.
/// Each batch resumes at the last key with a `0x00` byte appended, the exact
/// successor in the key ordering, so paging never skips or repeats a record.
///
/// Compacted pages are flushed to `scratch` and dropped from the cache before
/// every source read. That bounds the dirty set, and it is also required for
/// correctness: the compacted tree addresses the same page-id space as the
/// source and both are cached under the main file key, so a compacted page left
/// resident would answer a source read with the wrong page. After the drop, the
/// source reads come from the untouched `main.db` on disk.
pub(super) async fn stream_dense_tree<V: Vfs + Clone>(
    db: &Db<V>,
    scratch: &str,
    source_root: u64,
    source_next: u64,
    dest: &mut BTree<V>,
    keep: impl Fn(&[u8]) -> bool + Send,
) -> Result<()> {
    let source = BTree::open(
        db.pager.clone(),
        db.realm_id,
        source_root,
        source_next,
        db.page_size,
    );
    let mut loader = dest.bulk_loader_to(scratch)?;
    let mut cursor: Vec<u8> = Vec::new();
    loop {
        db.pager.flush_main_to(db.realm_id, scratch).await?;
        db.pager.reset_main_pages();

        let batch = source
            .collect_batch_from(&cursor, REPACK_RECORD_BATCH)
            .await?;
        let Some((last_key, _)) = batch.last() else {
            break;
        };
        cursor.clear();
        cursor.extend_from_slice(last_key);
        cursor.push(0);
        let exhausted = batch.len() < REPACK_RECORD_BATCH;

        // The value carries through by refcount; only the key, which the staged
        // record owns, is copied. The batch the source already handed over is
        // admitted in one call, so the loader sees the same bounded run of
        // records this loop holds rather than one Vec per record.
        let kept: Vec<(Vec<u8>, Bytes)> = batch
            .into_iter()
            .filter(|(key, _)| keep(key))
            .map(|(key, value)| (key.to_vec(), value))
            .collect();
        if !kept.is_empty() {
            loader.push_batch(kept).await?;
        }
        // A compacted page is written once and never read back, so flushing it
        // out between batches costs nothing and keeps the pool from growing
        // with the tree instead of with the budget. The reset is what makes the
        // next source read come from the untouched main.db rather than a
        // resident compacted page at the same page id.
        if db.pager.main_dirty_at_budget() {
            db.pager.flush_main_to(db.realm_id, scratch).await?;
            db.pager.reset_main_pages();
        }

        if exhausted {
            break;
        }
    }
    loader.finish().await
}

/// Catalog segment rows read per batch while compaction walks them. A row is a
/// fixed-width authenticated value plus a name capped at
/// `MAX_SEGMENT_NAME_LEN`, so one batch is a few hundred KiB resident however
/// many segments the catalog holds.
pub(super) const SEGMENT_ROW_BATCH: usize = 256;

/// Read one bounded batch of catalog segment rows at or after `cursor`, as
/// `(row key, decoded meta)` pairs.
///
/// Segment repack replaces a row's value under its own key, so key order is
/// stable across the mutations and a caller resumes on `key ‖ 0x00` — the exact
/// successor in the key ordering. The tree is opened per call from the live
/// writer state because each replacement commits a new catalog root. Holding one
/// batch is what keeps compaction's resident cost fixed instead of one
/// `SegmentMeta` per linked segment.
///
/// The row key carries the embedder name, so a caller that needs the name to
/// relink a replacement already has it here and never searches the catalog by
/// segment identity.
pub(super) async fn segment_rows_from<V: Vfs + Clone>(
    pager: &Arc<crate::pager::Pager<V>>,
    realm_id: crate::RealmId,
    state: &WriterState,
    cursor: &[u8],
) -> Result<Vec<(Vec<u8>, SegmentMeta)>> {
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
    let prefix = [CatalogRowKind::Segment as u8];
    let rows = tree
        .collect_prefix_batch_from(&prefix, cursor, SEGMENT_ROW_BATCH)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (key, value) in rows {
        let meta = Catalog::decode_segment_meta(&value)?;
        out.push((key.to_vec(), meta));
    }
    Ok(out)
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
    let header_cursor = db.pager.header_cursor()?;
    let new_seq = header_cursor.next_seq()?;
    let counter_anchor = db.pager.pending_anchor();

    let mut catalog_root_bytes = [0u8; 16];
    catalog_root_bytes[..8].copy_from_slice(&new_cat_root.to_le_bytes());
    catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());

    let fields = MainDbHeaderFields {
        format_version: crate::pager::structural_header::MAIN_FORMAT_VERSION,
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
        realm_id: db.realm_id,
    };

    let hk_clone = { db.hk.read().clone() };
    let new_slot = commit_header(
        &*db.vfs,
        &db.main_db_path,
        &hk_clone,
        &fields,
        header_cursor.slot,
        db.page_size,
    )
    .await?;
    db.pager.note_header_written(HeaderCursor {
        slot: new_slot,
        seq: new_seq,
    });
    // The catalog is durable at this point. Preserve its state internally but
    // retain the prior reader snapshot until segment replacement is reconciled.
    state.catalog_root_page_id = new_cat_root;
    state.catalog_root_txn_id = new_commit_id;
    state.next_page_id = new_next;
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
        format_version: crate::pager::structural_header::MAIN_FORMAT_VERSION,
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
        realm_id: db.realm_id,
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
