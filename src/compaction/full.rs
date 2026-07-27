//! Full one-shot compaction (entry point: [`compact_now`]):
//!
//! 1. Refuses while any reader pins the page range (relocation/truncation is
//!    unsafe under a pinned reader).
//! 2. Crash-atomically repacks the main + catalog trees into a dense low-address
//!    layout and truncates the reclaimed tail (see [`super::repack`]).
//! 3. Repacks segment files whose garbage ratio exceeds 5%.

use crate::Result;
use crate::catalog::codec::{Catalog, CatalogRowKind, SegmentMeta};
use crate::errors::PagedbError;
use crate::segment::reader::SegmentReader;
use crate::segment::types::SegmentPageKind;
use crate::segment::writer::SegmentWriter;
use crate::txn::db::{Db, WriterState};
use crate::vfs::{Vfs, VfsFile};

use super::helpers::{SEGMENT_ROW_BATCH, replace_segment_compact, segment_rows_from};
use super::types::CompactStats;

/// Full online compaction. See module-level docs for the staged flow.
///
/// The body is instrumented via [`tracing::Instrument`] rather than an
/// `EnteredSpan` guard: an entered span guard is `!Send` and would be held
/// across the many `.await` points below, making the returned future `!Send`
/// and thus uncallable from `Send` async contexts (e.g. the nodedb-lite
/// `#[async_trait]` `StorageEngine` impl, which requires `Send` futures).
pub async fn compact_now<V: Vfs + Clone>(db: &Db<V>) -> Result<CompactStats> {
    use tracing::Instrument;
    compact_now_inner(db)
        .instrument(tracing::debug_span!("compaction.run"))
        .await
}

#[allow(clippy::too_many_lines)]
async fn compact_now_inner<V: Vfs + Clone>(db: &Db<V>) -> Result<CompactStats> {
    db.ensure_usable()?;
    if !matches!(db.mode, crate::txn::mode::DbMode::Standalone) {
        return Err(PagedbError::Unsupported);
    }

    let mut result = CompactStats::default();

    // Acquire exclusive writer lock for the entire compact operation.
    let mut state = db.writer.lock().await;
    db.ensure_usable()?;
    #[cfg(test)]
    db.notify_writer_waiting();
    // Keep reader admission closed from the pin scan through the main-file
    // swap, directory sync, and published replacement snapshot.
    let visibility_guard = db.visibility_gate.write().await;

    // Compaction relocates and/or truncates pages, invalidating every page id
    // cached for runtime reuse. Drop those reuse hints so a post-compaction
    // commit can't recycle a page the repack now uses for live data.
    db.free_page_cache.lock().clear();

    // ── 1. Refuse while readers are pinned ───────────────────────────────────
    // A dense repack relocates the current tree and truncates the file; pinned
    // in-process readers still reference the old pages, so neither is safe
    // under them. Runtime free-page reuse already
    // reclaims space on ordinary commits, so there is nothing for compaction to
    // do here until the readers drop.
    let has_readers = {
        let readers = db.tracked_readers.lock();
        !readers.is_empty()
    };
    if has_readers {
        return Ok(result);
    }

    // ── 2. Crash-atomic dense repack of the main + catalog trees ─────────────
    // An empty free-list means every page below the high-water mark is live —
    // the store is already dense, so there is nothing to reclaim and we skip the
    // repack entirely (no wasted rewrite). Otherwise repack via a scratch file +
    // atomic rename; main.db is never modified until the rename (see
    // `super::repack`).
    if state.free_list_root_page_id != 0 {
        let repack = super::repack::atomic_dense_repack(db, &mut state, &visibility_guard).await?;
        result.main_db_pages_reclaimed = repack.pages_reclaimed;
        result.bytes_truncated = repack.bytes_truncated;
    }

    // ── 3. Repack segments ────────────────────────────────────────────────────
    // The catalog is streamed in bounded batches rather than listed: a repack
    // must not size an allocation by how many segments the embedder has linked.
    // Each replacement rewrites the row under its own key, so the cursor stays
    // valid across the mutation and resumes on `key ‖ 0x00`.
    let segment_prefix = [CatalogRowKind::Segment as u8];
    let mut cursor: Vec<u8> = segment_prefix.to_vec();
    loop {
        let batch = segment_rows_from(&db.pager, db.realm_id, &state, &cursor).await?;
        let Some((last_key, _)) = batch.last() else {
            break;
        };
        cursor.clear();
        cursor.extend_from_slice(last_key);
        cursor.push(0);
        let exhausted = batch.len() < SEGMENT_ROW_BATCH;

        for (key, meta) in batch {
            repack_one_segment(db, &mut state, &visibility_guard, &key, &meta, &mut result).await?;
        }

        if exhausted {
            break;
        }
    }

    Ok(result)
}

/// Repack one catalog-linked segment when its file carries more than 5% garbage,
/// republishing the replacement under the row's own name.
async fn repack_one_segment<V: Vfs + Clone>(
    db: &Db<V>,
    state: &mut WriterState,
    visibility_guard: &tokio::sync::RwLockWriteGuard<'_, ()>,
    key: &[u8],
    meta: &SegmentMeta,
    result: &mut CompactStats,
) -> Result<()> {
    let live = crate::segment::writer::live_path(&meta.segment_id);
    let file_size = db
        .vfs
        .open(&live, crate::vfs::types::OpenMode::Read)
        .await?
        .len()
        .await?;
    // Skip segments with < 5% garbage.
    let threshold = meta.total_bytes.saturating_add(meta.total_bytes / 20);
    if file_size <= threshold {
        return Ok(());
    }

    // The row key is `[kind] || realm_id || name`, so the name the replacement
    // must be relinked under comes straight from the row that carried this
    // meta. Validating it against the meta rejects a malformed key before the
    // repack republishes anything.
    let seg_name = String::from_utf8_lossy(Catalog::validate_segment_key(key, meta)?).into_owned();

    let mmap_limit = u64::try_from(db.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
    let reader = SegmentReader::open_internal(
        db.pager.clone(),
        meta.clone(),
        db.mmap_bytes_in_use.clone(),
        mmap_limit,
    )
    .await?;
    db.vfs.mkdir_all("seg/.staging").await?;
    let new_segment_id = crate::crypto::random::segment_id()?;
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
    replace_segment_compact(
        db,
        state,
        visibility_guard,
        &seg_name,
        &meta.segment_id,
        &new_meta,
    )
    .await?;
    result.segments_repacked += 1;
    Ok(())
}
