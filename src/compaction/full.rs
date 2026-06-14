//! Full one-shot compaction (entry point: [`compact_now`]):
//!
//! 1. Collects all live data from main and catalog trees into memory.
//! 2. Drains eligible deferred-free pages (now eligible since no pinned reader
//!    can observe them).
//! 3. Writes fresh compacted trees starting at page 4, producing a dense layout.
//! 4. Commits a new header with the updated roots and reduced `next_page_id`.
//! 5. Truncates main.db if no reader pins the old high-water-mark range.
//! 6. Repacks segment files whose garbage ratio exceeds 5%.

use crate::btree::BTree;
use crate::errors::PagedbError;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::segment::reader::SegmentReader;
use crate::segment::types::SegmentPageKind;
use crate::segment::writer::SegmentWriter;
use crate::txn::db::Db;
use crate::vfs::{Vfs, VfsFile};
use crate::{CommitId, Result};

use super::helpers::{
    collect_all_pairs, collect_catalog_split, find_segment_name_inner, list_all_segments_inner,
    page_size_log2, replace_segment_compact,
};
use super::types::CompactStats;

/// Full online compaction. See module-level docs for the staged flow.
///
/// The body is instrumented via [`tracing::Instrument`] rather than an
/// `EnteredSpan` guard: an entered span guard is `!Send` and would be held
/// across the many `.await` points below, making the returned future `!Send`
/// and thus uncallable from `Send` async contexts (e.g. the nodedb-lite
/// `#[async_trait]` StorageEngine impl, which requires `Send` futures).
pub async fn compact_now<V: Vfs + Clone>(db: &Db<V>) -> Result<CompactStats> {
    use tracing::Instrument;
    compact_now_inner(db)
        .instrument(tracing::debug_span!("compaction.run"))
        .await
}

#[allow(clippy::too_many_lines)]
async fn compact_now_inner<V: Vfs + Clone>(db: &Db<V>) -> Result<CompactStats> {
    if !matches!(db.mode, crate::txn::mode::DbMode::Standalone) {
        return Err(PagedbError::Unsupported);
    }

    let mut result = CompactStats::default();

    // Acquire exclusive writer lock for the entire compact operation.
    let mut state = db.writer.lock().await;

    // Compaction relocates and/or truncates pages, invalidating every page id
    // cached for runtime reuse. Drop those reuse hints so a post-compaction
    // commit can't recycle a page the repack now uses for live data.
    db.free_page_cache.lock().clear();

    let old_next_page_id = state.next_page_id;

    // ── 1. Refuse while readers are pinned ───────────────────────────────────
    // A dense repack relocates the current tree and truncates the file; pinned
    // readers (in-process or cross-process durable) still reference the old
    // pages, so neither is safe under them. Runtime free-page reuse already
    // reclaims space on ordinary commits, so there is nothing for compaction to
    // do here until the readers drop.
    let has_readers = {
        let in_mem_min = {
            let readers = db.tracked_readers.lock();
            readers
                .iter()
                .map(|r| r.commit_id.0)
                .min()
                .unwrap_or(u64::MAX)
        };
        let durable_min = db
            .min_durable_reader_commit(state.catalog_root_page_id, state.next_page_id)
            .await;
        in_mem_min.min(durable_min) < u64::MAX
    };
    if has_readers {
        return Ok(result);
    }

    // ── 2. Full repack (no readers pinned) ───────────────────────────────────

    // Collect all live data in memory BEFORE any writes.
    let main_pairs = if state.root_page_id != 0 {
        let old_tree = BTree::open(
            db.pager.clone(),
            db.realm_id,
            state.root_page_id,
            old_next_page_id,
            db.page_size,
        );
        collect_all_pairs(&old_tree).await?
    } else {
        Vec::new()
    };

    // Collect catalog rows (housekeeping free-list rows dropped).
    let cat_rows = collect_catalog_split(&db.pager, db.realm_id, &state).await?;

    // ── 3. Write fresh compacted trees starting at page 4 ────────────────────
    // Pages 0–3 are reserved (header slots A/B + two spares); never allocated.
    let mut new_main = BTree::open(
        db.pager.clone(),
        db.realm_id,
        0,
        4, // first data page (pages 0-3 are reserved header slots)
        db.page_size,
    );
    new_main.bulk_load(main_pairs).await?;
    new_main.flush().await?;
    let new_root = new_main.root_page_id();
    let after_main = new_main.next_page_id();

    let mut new_cat = BTree::open(db.pager.clone(), db.realm_id, 0, after_main, db.page_size);
    new_cat.bulk_load(cat_rows).await?;
    new_cat.flush().await?;
    let new_cat_root = new_cat.root_page_id();
    let new_next = new_cat.next_page_id();

    // Pages reclaimed = reduction in next_page_id (the dense layout is contiguous,
    // and the durable free-list is reset to empty below).
    result.main_db_pages_reclaimed = old_next_page_id.saturating_sub(new_next);

    // ── 4. Commit new header ─────────────────────────────────────────────────
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
        active_root_page_id: new_root,
        active_root_txn_id: new_commit_id,
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

    state.root_page_id = new_root;
    state.catalog_root_page_id = new_cat_root;
    state.next_page_id = new_next;
    state.active_slot = new_slot;
    state.seq = new_seq;
    state.latest_commit_id = new_commit_id;
    state.commit_history_root_page_id = 0;
    state.commit_history_root_version = 0;
    // The dense repack relocates/truncates every page, so the old free-list is
    // gone; the new layout starts with an empty free-list.
    state.free_list_root_page_id = 0;
    db.latest_commit
        .store(new_commit_id, std::sync::atomic::Ordering::SeqCst);

    // ── 5. Truncate if no readers pin the old high-water range ───────────────
    // (No readers are pinned at this point — checked above — so truncation is safe.)
    if new_next < old_next_page_id {
        let new_size = new_next.saturating_mul(db.page_size as u64);
        let old_size = old_next_page_id.saturating_mul(db.page_size as u64);
        let mut f = db
            .vfs
            .open(&db.main_db_path, crate::vfs::types::OpenMode::ReadWrite)
            .await?;
        f.set_len(new_size).await?;
        f.sync().await?;
        result.bytes_truncated = old_size.saturating_sub(new_size);
    }

    // ── 6. Repack segments ────────────────────────────────────────────────────
    let all_segments = list_all_segments_inner(&db.pager, db.realm_id, &state).await?;
    for meta in all_segments {
        let live = crate::segment::writer::live_path(&meta.segment_id);
        let file_size = match db.vfs.open(&live, crate::vfs::types::OpenMode::Read).await {
            Ok(f) => f.len().await.unwrap_or(meta.total_bytes),
            Err(_) => continue,
        };
        // Skip segments with < 5% garbage.
        let threshold = meta.total_bytes.saturating_add(meta.total_bytes / 20);
        if file_size <= threshold {
            continue;
        }

        let mmap_limit = u64::try_from(db.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        let reader = SegmentReader::open_internal(
            db.pager.clone(),
            meta.clone(),
            db.mmap_bytes_in_use.clone(),
            mmap_limit,
        )
        .await?;
        db.vfs.mkdir_all("seg/.staging").await?;
        let new_segment_id = db.next_segment_id();
        let mut writer = SegmentWriter::create_internal(
            db.pager.clone(),
            meta.realm_id,
            new_segment_id,
            db.file_id,
            meta.segment_kind,
        )
        .await?;

        for page_id in 1..meta.page_count.saturating_sub(1) {
            match reader.read_page(page_id).await {
                Ok(page_bytes) => {
                    writer
                        .append_page(SegmentPageKind::Data, &page_bytes)
                        .await?;
                }
                Err(PagedbError::NotFound) => {}
                Err(e) => return Err(e),
            }
        }

        let new_meta = writer.seal().await?;
        let seg_name =
            find_segment_name_inner(&db.pager, db.realm_id, &state, &meta.segment_id).await?;
        replace_segment_compact(db, &mut state, &seg_name, &meta.segment_id, &new_meta).await?;
        result.segments_repacked += 1;
    }

    Ok(result)
}
