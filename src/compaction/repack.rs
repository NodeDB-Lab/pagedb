//! Crash-atomic dense repack of the main and catalog B+ trees.
//!
//! The compacted trees are built into a scratch file (`main.db.compact`) that is
//! then **atomically renamed** over `main.db`. `main.db` is never modified until
//! the rename, so a failure or crash at any point before it leaves the original
//! store fully intact (the orphaned scratch is removed on the next open); after
//! the rename the compacted store is live. The rename is the single commit point.
//!
//! Pages are written through the existing pager (one nonce counter — no reuse)
//! to the scratch path; the scratch is a bit-identical `main.db` (same AAD), so
//! it opens directly once renamed. The data is written once.
//!
//! The rebuild streams: the old trees are read in bounded batches and the
//! compacted pages are flushed to the scratch as they accumulate, so neither the
//! dataset nor the new tree is ever held whole. The header goes in after the
//! last flush — the scratch is inert until the rename either way.

use crate::Result;
use crate::btree::BTree;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::{ActiveSlot, commit_header};
use crate::txn::db::{Db, WriterState};
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

use super::helpers::{make_header_fields, stream_dense_tree};

/// Pages 0-3 of a `main.db` are the A/B headers and their spare slots; data
/// pages start above them, so a compacted image does too.
const RESERVED_PAGES: u64 = 4;

/// Outcome of an atomic dense repack.
pub(super) struct RepackOutcome {
    pub pages_reclaimed: u64,
    pub bytes_truncated: u64,
}

/// The compacted layout built in the scratch file, awaiting the atomic rename.
pub(super) struct PendingSwap {
    new_root: u64,
    new_cat_root: u64,
    new_next: u64,
    counter_anchor: u64,
    old_next: u64,
    /// Sequence the scratch's own header carries. After the rename that header
    /// is the live one, so the A/B cursor continues from it.
    header_seq: u64,
}

/// Path of the scratch file compaction builds before renaming it over main.db.
fn scratch_path(db: &Db<impl Vfs + Clone>) -> String {
    format!("{}.compact", db.main_db_path)
}

/// Rebuild the main + catalog trees into a dense, low-addressed layout, crash-
/// atomically (see module docs). On success `state` points at the compacted
/// layout. On failure the partially built scratch and the never-persisted cache
/// pages are discarded and `state`/main.db are left untouched.
pub(super) async fn atomic_dense_repack<V: Vfs + Clone>(
    db: &Db<V>,
    state: &mut WriterState,
    visibility: &tokio::sync::RwLockWriteGuard<'_, ()>,
) -> Result<RepackOutcome> {
    let scratch = scratch_path(db);
    // Remove any leftover scratch from an earlier interrupted compaction.
    db.vfs.remove(&scratch).await.ok();

    match build_scratch(db, state, &scratch).await {
        Ok(pending) => commit_swap(db, state, visibility, &scratch, pending).await,
        Err(e) => {
            // Nothing was written to main.db; drop the never-persisted compacted
            // pages from the cache so the old tree is read back from disk, and
            // remove the partial scratch.
            db.pager.reset_main_pages();
            db.vfs.remove(&scratch).await.ok();
            Err(e)
        }
    }
}

/// Build the compacted trees into `scratch` (a complete, bit-identical main.db)
/// without touching the live main.db or `state`. Returns the layout to be
/// swapped in.
///
/// The source is streamed in bounded batches into a push-style bulk loader and
/// the compacted pages are flushed to `scratch` as they accumulate, so what the
/// repack holds resident is one batch of source records, one leaf, and one
/// internal node per level — never the dataset or the new tree. The scratch
/// header is still written last, after the final flush, so the rename stays the
/// only commit point: an interrupted repack leaves a scratch file that describes
/// nothing.
pub(super) async fn build_scratch<V: Vfs + Clone>(
    db: &Db<V>,
    state: &WriterState,
    scratch: &str,
) -> Result<PendingSwap> {
    let old_next = state.next_page_id;

    // Pre-size and zero the reserved header/spare pages (0-3, including the
    // unused B header slot) before anything is flushed, so the scratch is a
    // well-defined main.db image from its first byte and the streamed data pages
    // simply extend it.
    {
        let mut f = db.vfs.open(scratch, OpenMode::CreateOrOpen).await?;
        f.set_len(RESERVED_PAGES.saturating_mul(db.page_size as u64))
            .await?;
        f.sync().await?;
    }

    // Stream the live data into dense trees starting above the reserved pages.
    // These writes land in the pager cache as dirty main pages and are flushed
    // to the scratch file in bounded rounds, never to main.db.
    let mut new_main = BTree::open(
        db.pager.clone(),
        db.realm_id,
        0,
        RESERVED_PAGES,
        db.page_size,
    );
    stream_dense_tree(
        db,
        scratch,
        state.root_page_id,
        old_next,
        &mut new_main,
        |_| true,
    )
    .await?;
    let new_root = new_main.root_page_id();
    let after_main = new_main.next_page_id();

    // Drop the compaction watermark row: a fully repacked tree is compact, so
    // any resumable `compact_step` state is stale and must not carry forward.
    // Free pages live in the durable free-list chain (reset separately by the
    // repack), not in the catalog, so nothing else needs filtering here.
    let cs_prefix = crate::catalog::codec::CatalogRowKind::CompactionState as u8;
    let mut new_cat = BTree::open(db.pager.clone(), db.realm_id, 0, after_main, db.page_size);
    stream_dense_tree(
        db,
        scratch,
        state.catalog_root_page_id,
        old_next,
        &mut new_cat,
        |key: &[u8]| key.first() != Some(&cs_prefix),
    )
    .await?;
    let new_cat_root = new_cat.root_page_id();
    let new_next = new_cat.next_page_id();

    // Grow the scratch to the exact compacted length. The streamed flushes have
    // already written every page below `new_next`, so this only ever extends.
    {
        let mut f = db.vfs.open(scratch, OpenMode::CreateOrOpen).await?;
        f.set_len(new_next.saturating_mul(db.page_size as u64))
            .await?;
        f.sync().await?;
    }

    // Flush the compacted pages the last streaming round left dirty. The header
    // is written after this, so the scratch is complete before the file claims
    // to describe it.
    db.pager.flush_main_to(db.realm_id, scratch).await?;

    // Write the scratch header into slot A (passing B as "previous" so
    // `commit_header` targets A). The anchor is snapshotted after the flush so
    // it covers every nonce the flush consumed — including the ones the rebuild's
    // anchor refreshes already made durable in the live header.
    let new_commit_id = state.latest_commit_id + 1;
    let new_seq = db.pager.header_cursor()?.next_seq()?;
    let counter_anchor = db.pager.pending_anchor();
    let fields = make_header_fields(
        db,
        state,
        new_commit_id,
        new_seq,
        counter_anchor,
        new_root,
        new_cat_root,
        new_next,
        0,
    );
    let hk_clone = { db.hk.read().clone() };
    commit_header(
        &*db.vfs,
        scratch,
        &hk_clone,
        &fields,
        ActiveSlot::B,
        db.page_size,
    )
    .await?;

    Ok(PendingSwap {
        new_root,
        new_cat_root,
        new_next,
        counter_anchor,
        old_next,
        header_seq: new_seq,
    })
}

/// Atomically swap the scratch file in for main.db and advance `state`. This is
/// the commit point: a crash before the rename keeps the old store; after it the
/// compacted store is live.
async fn commit_swap<V: Vfs + Clone>(
    db: &Db<V>,
    state: &mut WriterState,
    visibility: &tokio::sync::RwLockWriteGuard<'_, ()>,
    scratch: &str,
    pending: PendingSwap,
) -> Result<RepackOutcome> {
    // Close the cached main.db handle so the rename can replace the file
    // (Windows) and the next access reopens the new inode (Unix).
    db.pager.close_main_handle().await;
    let new_commit_id = state.latest_commit_id + 1;
    if db.vfs.rename(scratch, &db.main_db_path).await.is_err() {
        // After closing the old handle, a backend may have performed an
        // ambiguous replacement even when it reports an error. Reopen is the
        // only safe way to establish the durable image.
        let commit = crate::CommitId(new_commit_id);
        db.poison(commit);
        return Err(crate::errors::PagedbError::durably_committed_but_unpublished(commit));
    }

    // Rename is the durable-image boundary. Advance internal state and drop
    // cache pages immediately, but do not publish until the parent directory
    // sync and nonce-anchor commit both succeed.
    state.root_page_id = pending.new_root;
    state.catalog_root_page_id = pending.new_cat_root;
    state.catalog_root_txn_id = new_commit_id;
    state.next_page_id = pending.new_next;
    // The scratch is `main.db` now: its only verifiable header is the one
    // `build_scratch` wrote into slot A. Whatever anchor refreshes the rebuild
    // wrote into the replaced file went with it, and this header's anchor covers
    // every nonce they did.
    db.pager.note_header_written(HeaderCursor {
        slot: ActiveSlot::A,
        seq: pending.header_seq,
    });
    state.latest_commit_id = new_commit_id;
    state.commit_history_root_page_id = 0;
    state.commit_history_root_version = 0;
    state.free_list_root_page_id = 0;
    db.pager.reset_main_pages();

    if db.vfs.sync_dir(db.main_db_parent_dir()).await.is_err() {
        let commit = crate::CommitId(new_commit_id);
        db.poison(commit);
        return Err(crate::errors::PagedbError::durably_committed_but_unpublished(commit));
    }
    let _ = db
        .finish_durable_commit_visible(
            visibility,
            state,
            crate::CommitId(new_commit_id),
            pending.counter_anchor,
            &[],
        )
        .await?;

    let pages_reclaimed = pending.old_next.saturating_sub(pending.new_next);
    Ok(RepackOutcome {
        pages_reclaimed,
        bytes_truncated: pages_reclaimed.saturating_mul(db.page_size as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::memory::MemVfs;
    use crate::{Db, OpenOptions, RealmId};

    /// A repack must run inside the configured buffer-pool budget however large
    /// the store is. Both halves of the streaming rebuild are under test: the
    /// source is read in bounded batches instead of being materialised, and the
    /// compacted pages are flushed out as they are built instead of being held
    /// dirty — dirty pages are never evicted, so holding the whole new tree
    /// would defeat the budget on its own.
    ///
    /// Exactly one rebuild runs here. A dense repack consumes one nonce per
    /// compacted page and cannot commit an anchor until its header lands, so a
    /// second pass over a store this size would exhaust the anchor budget and
    /// abort before proving anything about memory.
    /// A repack must succeed on a store whose compacted image is larger than the
    /// nonce anchor budget. The repack writes no header until the rename, and
    /// only a durable header advances the anchor, so the whole rebuild draws
    /// nonces from one window — if nothing refreshes that window, compaction
    /// stops working above a fixed store size regardless of how much memory or
    /// disk is available.
    #[tokio::test(flavor = "current_thread")]
    async fn repack_succeeds_on_a_store_larger_than_the_anchor_budget() {
        let vfs = MemVfs::new();
        let kek = [0x51u8; 32];
        let realm = RealmId::new([0xB2u8; 16]);
        // Deliberately small so the store only has to outgrow *this*, not the
        // 1024-page default: the property under test is "larger than the
        // budget", not any particular byte size.
        let options = OpenOptions::default().with_anchor_budget(64);
        let db = Db::open_internal_with_options(vfs.clone(), kek, 4096, realm, options)
            .await
            .unwrap();

        let spilled = vec![0xD4u8; 3000]; // each value takes an overflow page
        for round in 0..8u32 {
            let mut w = db.begin_write().await.unwrap();
            for i in 0..40u32 {
                w.put(format!("a-{round:02}-{i:04}").as_bytes(), &spilled)
                    .await
                    .unwrap();
            }
            w.commit().await.unwrap();
        }

        let compacted_pages = {
            let state = db.writer.lock().await;
            build_scratch(&db, &state, &scratch_path(&db))
                .await
                .expect("a repack must not be bounded by the anchor budget")
                .new_next
        };
        assert!(
            compacted_pages > 64,
            "the compacted image must exceed the anchor budget for this to prove \
             anything; got {compacted_pages} pages"
        );
    }

    /// The rebuild must make its own nonces durable as it goes, not merely fit
    /// inside a wider window. One window can carry at most `budget` nonces, so an
    /// anchor that ends more than a whole budget above where it started can only
    /// have been advanced *during* the rebuild.
    #[tokio::test(flavor = "current_thread")]
    async fn a_repack_advances_the_durable_anchor_during_the_rebuild() {
        const BUDGET: u64 = 64;
        let vfs = MemVfs::new();
        let kek = [0x77u8; 32];
        let realm = RealmId::new([0x1Du8; 16]);
        let options = OpenOptions::default().with_anchor_budget(BUDGET);
        let db = Db::open_internal_with_options(vfs.clone(), kek, 4096, realm, options)
            .await
            .unwrap();

        let spilled = vec![0x9Bu8; 3000]; // each value takes an overflow page
        for round in 0..8u32 {
            let mut w = db.begin_write().await.unwrap();
            for i in 0..40u32 {
                w.put(format!("a-{round:02}-{i:04}").as_bytes(), &spilled)
                    .await
                    .unwrap();
            }
            w.commit().await.unwrap();
        }

        let before = db.pager.durable_anchor();
        {
            let state = db.writer.lock().await;
            build_scratch(&db, &state, &scratch_path(&db))
                .await
                .unwrap();
        }
        let after = db.pager.durable_anchor();
        assert!(
            after > before.saturating_add(BUDGET),
            "the rebuild must advance the anchor past a whole window; it moved \
             from {before} to {after} with a budget of {BUDGET}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn repack_of_a_store_larger_than_the_pool_stays_inside_the_budget() {
        const BUDGET: usize = 32;
        let vfs = MemVfs::new();
        let kek = [0x24u8; 32];
        let realm = RealmId::new([0x9u8; 16]);
        let options = OpenOptions::default().with_buffer_pool_pages(BUDGET);
        let db = Db::open_internal_with_options(vfs.clone(), kek, 4096, realm, options)
            .await
            .unwrap();

        let inline = vec![0x3Cu8; 300];
        let spilled = vec![0xE1u8; 3000]; // > page_size/4 → overflow chain
        for round in 0..20u32 {
            let mut w = db.begin_write().await.unwrap();
            for i in 0..100u32 {
                let key = format!("k-{round:02}-{i:04}");
                let value = if i % 5 == 0 { &spilled } else { &inline };
                w.put(key.as_bytes(), value).await.unwrap();
            }
            w.commit().await.unwrap();
        }

        // Rebuild the whole main tree exactly as a repack does, then sample the
        // pool on return. That is a high-water point, not a trough: the stream
        // flushes and drops only at the top of a round and when the dirty set
        // reaches the budget — never on the way out — so what is resident here
        // is everything written since the last flush plus the tail `finish`
        // just wrote. Held-whole behaviour would show up as the entire new tree,
        // because dirty pages are never evicted.
        let state = db.writer.lock().await;
        let mut compacted = BTree::open(
            db.pager.clone(),
            db.realm_id,
            0,
            RESERVED_PAGES,
            db.page_size,
        );
        stream_dense_tree(
            &db,
            &scratch_path(&db),
            state.root_page_id,
            state.next_page_id,
            &mut compacted,
            |_| true,
        )
        .await
        .unwrap();
        let resident = db.pager.inner.buffer_pool.lock().len();
        let compacted_pages = compacted.next_page_id().saturating_sub(RESERVED_PAGES);

        assert!(
            compacted_pages > BUDGET as u64 * 10,
            "the store must be far larger than the budget for this to prove \
             anything; the compacted tree is {compacted_pages} pages"
        );
        assert!(
            resident <= BUDGET * 3,
            "a repack must stay inside the {BUDGET}-page buffer-pool budget; \
             {resident} pages resident after streaming {compacted_pages} pages"
        );
    }

    /// Model a crash *before* the atomic rename: build the scratch file but never
    /// swap it in, then reopen. main.db must be untouched and every value —
    /// including overflow-backed ones — intact, proving the pre-rename work is
    /// non-destructive. The orphaned scratch must also be gone after reopen.
    #[tokio::test(flavor = "current_thread")]
    async fn crash_before_rename_leaves_old_store_intact() {
        let vfs = MemVfs::new();
        let kek = [0x42u8; 32];
        let realm = RealmId::new([0x7u8; 16]);
        let big = vec![0xABu8; 2048]; // > page_size/4 → overflow chain
        let n = 50u32;

        {
            let db = Db::open_internal(vfs.clone(), kek, 4096, realm)
                .await
                .unwrap();
            {
                let mut w = db.begin_write().await.unwrap();
                for i in 0..n {
                    w.put(format!("k-{i:04}").as_bytes(), &big).await.unwrap();
                }
                w.commit().await.unwrap();
            }
            // Build the scratch copy but never commit the swap (simulated crash).
            {
                let state = db.writer.lock().await;
                let scratch = scratch_path(&db);
                build_scratch(&db, &state, &scratch).await.unwrap();
            }
        }

        // Reopen: main.db is the original, intact; the orphan scratch is removed.
        let db2 = Db::open_existing(vfs.clone(), kek, 4096, realm)
            .await
            .unwrap();
        let r = db2.begin_read().await.unwrap();
        for i in 0..n {
            let key = format!("k-{i:04}");
            assert_eq!(
                r.get(key.as_bytes()).await.unwrap().as_deref(),
                Some(big.as_slice()),
                "value {key} lost after a crash before the compaction rename"
            );
        }
        assert!(
            vfs.open("/main.db.compact", OpenMode::Read).await.is_err(),
            "orphaned compaction scratch should be removed on open"
        );
    }
}
