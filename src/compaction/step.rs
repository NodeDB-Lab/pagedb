//! Incremental, budget-bounded compaction (entry point: [`compact_step`]).

use crate::Result;
use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CompactionStateRow};
use crate::errors::PagedbError;
use crate::pager::header::commit_header;
use crate::txn::db::Db;
use crate::vfs::{Vfs, VfsFile};

use super::helpers::{
    collect_all_pairs, collect_catalog_split, collect_range_limited, load_compaction_state,
    load_frontier_page_id, make_header_fields, next_key_after,
};
use super::types::{CompactBudget, CompactProgress};

/// Incremental compaction step.
///
/// Processes up to `budget.max_pages_relocated` key-value pairs per call,
/// holding the writer lock only for the duration of a single batch commit.
/// After each call the watermark row (`CatalogRowKind::CompactionState`) is
/// updated atomically with the batch commit. The next call resumes from the
/// persisted frontier.
///
/// Returns `PagedbError::Unsupported` if the handle is not in `Standalone` mode.
#[allow(clippy::too_many_lines)]
pub async fn compact_step<V: Vfs + Clone>(
    db: &Db<V>,
    budget: CompactBudget,
) -> Result<CompactProgress> {
    if !matches!(db.mode, crate::txn::mode::DbMode::Standalone) {
        return Err(PagedbError::Unsupported);
    }

    let mut state = db.writer.lock().await;

    // Relocation/truncation below invalidates cached reuse page ids; drop them.
    db.free_page_cache.lock().clear();

    // ── Refuse while readers are pinned ───────────────────────────────────────
    // Relocation/truncation is unsafe under a pinned reader (in-process or
    // cross-process durable). Runtime free-page reuse reclaims space on ordinary
    // commits, so compaction simply waits for the readers to drop.
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
        let wm = load_frontier_page_id(&db.pager, db.realm_id, &state).await;
        return Ok(CompactProgress {
            pages_relocated: 0,
            bytes_freed: 0,
            more_work: true,
            watermark: wm,
        });
    }

    // ── No readers pinned: do a compaction batch ──────────────────────────────

    let compaction_state = load_compaction_state(&db.pager, db.realm_id, &state).await?;

    let (frontier_key, started_at_commit_id, total_pages_estimate) =
        if let Some(cs) = &compaction_state {
            (
                cs.frontier_key.clone(),
                cs.started_at_commit_id,
                cs.total_pages_estimate,
            )
        } else {
            let est = state.next_page_id.saturating_sub(4);
            (Vec::new(), state.latest_commit_id, est)
        };

    let old_next_page_id = state.next_page_id;

    // Collect the next batch of pairs from the current live main tree.
    let pairs_batch: Vec<(Vec<u8>, Vec<u8>)> = if state.root_page_id != 0 {
        let source = BTree::open(
            db.pager.clone(),
            db.realm_id,
            state.root_page_id,
            state.next_page_id,
            db.page_size,
        );
        let end_sentinel = vec![0xFFu8; 256];
        let start = next_key_after(&frontier_key);
        collect_range_limited(&source, &start, &end_sentinel, budget.max_pages_relocated).await?
    } else {
        Vec::new()
    };

    let pairs_count = pairs_batch.len() as u64;

    // If the batch came back empty AND there was no prior frontier (fresh call
    // on an already-empty or truly compact tree), nothing to do.
    if pairs_count == 0 && frontier_key.is_empty() && compaction_state.is_none() {
        return Ok(CompactProgress {
            pages_relocated: 0,
            bytes_freed: 0,
            more_work: false,
            watermark: None,
        });
    }

    // Fewer items than budget → this is the final batch.
    let session_complete = pairs_count < budget.max_pages_relocated;

    if session_complete {
        // Final pass: do the full repack starting at page 4, then truncate.
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

        let cat_rows = collect_catalog_split(&db.pager, db.realm_id, &state).await?;

        let mut new_main = BTree::open(db.pager.clone(), db.realm_id, 0, 4, db.page_size);
        new_main.bulk_load(main_pairs).await?;
        new_main.flush().await?;
        let new_root = new_main.root_page_id();
        let after_main = new_main.next_page_id();

        // Remove compaction-state row from the catalog being rebuilt.
        let cs_key_prefix = crate::catalog::codec::CatalogRowKind::CompactionState as u8;
        let mut cat_all: Vec<(Vec<u8>, Vec<u8>)> = cat_rows
            .into_iter()
            .filter(|(k, _)| k.first() != Some(&cs_key_prefix))
            .collect();
        cat_all.sort_by(|(a, _), (b, _)| a.cmp(b));
        let mut new_cat = BTree::open(db.pager.clone(), db.realm_id, 0, after_main, db.page_size);
        new_cat.bulk_load(cat_all).await?;
        new_cat.flush().await?;
        let new_cat_root = new_cat.root_page_id();
        let new_next = new_cat.next_page_id();

        let pages_reclaimed = old_next_page_id.saturating_sub(new_next);

        let new_commit_id = state.latest_commit_id + 1;
        let new_seq = state.seq + 1;
        let counter_anchor = db.pager.pending_anchor();
        // Dense repack: the relocated layout starts with an empty free-list.
        let fields = make_header_fields(
            db,
            &state,
            new_commit_id,
            new_seq,
            counter_anchor,
            new_root,
            new_cat_root,
            new_next,
            0,
        );
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
        state.free_list_root_page_id = 0;
        db.latest_commit
            .store(new_commit_id, std::sync::atomic::Ordering::SeqCst);

        let mut bytes_freed = 0u64;
        if new_next < old_next_page_id {
            let new_size = new_next.saturating_mul(db.page_size as u64);
            let old_size = old_next_page_id.saturating_mul(db.page_size as u64);
            let mut f = db
                .vfs
                .open(&db.main_db_path, crate::vfs::types::OpenMode::ReadWrite)
                .await?;
            f.set_len(new_size).await?;
            f.sync().await?;
            bytes_freed = old_size.saturating_sub(new_size);
        }

        return Ok(CompactProgress {
            pages_relocated: pages_reclaimed,
            bytes_freed,
            more_work: false,
            watermark: None,
        });
    }

    // ── Intermediate step: re-insert batch via CoW to defragment ─────────────
    let new_frontier_key = pairs_batch
        .last()
        .map_or_else(|| frontier_key.clone(), |(k, _)| k.clone());

    let mut cat_tree = BTree::open(
        db.pager.clone(),
        db.realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        db.page_size,
    );

    // Re-insert the batch: delete+put forces page reallocation to low-address
    // free slots. Pages freed by the delete are recycled within this same txn
    // (the allocator pops the per-session freed list), so the subsequent put
    // reuses them — densifying the layout into the low page-id range.
    let mut main_tree = BTree::open(
        db.pager.clone(),
        db.realm_id,
        state.root_page_id,
        state.next_page_id,
        db.page_size,
    );
    for (k, v) in &pairs_batch {
        main_tree.delete(k).await?;
        main_tree.put(k, v).await?;
    }

    main_tree.flush().await?;
    // main_tree.flush() may allocate pages while materializing the dirty-leaf
    // cache. Sync the catalog tree forward so its flush doesn't reuse a
    // page_id the main tree just claimed.
    cat_tree.set_next_page_id(main_tree.next_page_id());
    cat_tree.flush().await?;

    let new_main_root = main_tree.root_page_id();
    let after_main_step = main_tree.next_page_id();
    let cat_root_step = cat_tree.root_page_id();
    let next_step = cat_tree.next_page_id().max(after_main_step);

    // Update compaction watermark.
    let mut cat_tree2 = BTree::open(
        db.pager.clone(),
        db.realm_id,
        cat_root_step,
        next_step,
        db.page_size,
    );
    let new_cs = CompactionStateRow {
        target_root: state.root_page_id,
        frontier_page_id: next_step,
        started_at_commit_id,
        total_pages_estimate,
        frontier_key: new_frontier_key.clone(),
    };
    let cs_key = Catalog::compaction_state_key();
    let cs_val = Catalog::encode_compaction_state(&new_cs)?;
    cat_tree2.put(&cs_key, &cs_val).await?;
    cat_tree2.flush().await?;
    let final_cat_root = cat_tree2.root_page_id();
    let final_next = cat_tree2.next_page_id().max(next_step);

    let new_commit_id = state.latest_commit_id + 1;
    let new_seq = state.seq + 1;
    let counter_anchor = db.pager.pending_anchor();
    // An intermediate step only relocates main-tree pages; it touches neither
    // the durable free-list chain nor its free pages, so the free-list stays
    // valid and is preserved across the step (the pre-existing free pages remain
    // reusable by ordinary writes). The final dense-repack batch resets it.
    let fields = make_header_fields(
        db,
        &state,
        new_commit_id,
        new_seq,
        counter_anchor,
        new_main_root,
        final_cat_root,
        final_next,
        state.free_list_root_page_id,
    );
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

    state.root_page_id = new_main_root;
    state.catalog_root_page_id = final_cat_root;
    state.next_page_id = final_next;
    state.active_slot = new_slot;
    state.seq = new_seq;
    state.latest_commit_id = new_commit_id;
    state.commit_history_root_page_id = 0;
    state.commit_history_root_version = 0;
    db.latest_commit
        .store(new_commit_id, std::sync::atomic::Ordering::SeqCst);

    Ok(CompactProgress {
        pages_relocated: pairs_count,
        bytes_freed: 0,
        more_work: true,
        watermark: Some(next_step),
    })
}
