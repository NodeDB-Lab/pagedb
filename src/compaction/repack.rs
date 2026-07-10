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

use crate::Result;
use crate::btree::BTree;
use crate::pager::header::{ActiveSlot, commit_header};
use crate::txn::db::{Db, WriterState};
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

use super::helpers::{collect_all_pairs, collect_catalog_split, make_header_fields};

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
/// without touching the live main.db or `state`. The compacted pages are written
/// through the pager cache then flushed to `scratch`; the scratch header is
/// written last. Returns the layout to be swapped in.
pub(super) async fn build_scratch<V: Vfs + Clone>(
    db: &Db<V>,
    state: &WriterState,
    scratch: &str,
) -> Result<PendingSwap> {
    let old_next = state.next_page_id;

    // Collect all live data, then bulk-load dense trees starting at page 4
    // (pages 0-3 are reserved header/spare slots). These writes land in the
    // pager cache as dirty main pages; they are flushed to the scratch file,
    // never to main.db.
    let main_pairs = if state.root_page_id != 0 {
        let old = BTree::open(
            db.pager.clone(),
            db.realm_id,
            state.root_page_id,
            old_next,
            db.page_size,
        );
        collect_all_pairs(&old).await?
    } else {
        Vec::new()
    };

    // Drop the compaction watermark row: a fully repacked tree is compact, so
    // any resumable `compact_step` state is stale and must not carry forward.
    let cs_prefix = crate::catalog::codec::CatalogRowKind::CompactionState as u8;
    let cat_rows: Vec<(Vec<u8>, Vec<u8>)> = collect_catalog_split(&db.pager, db.realm_id, state)
        .await?
        .into_iter()
        .filter(|(k, _)| k.first() != Some(&cs_prefix))
        .collect();

    let mut new_main = BTree::open(db.pager.clone(), db.realm_id, 0, 4, db.page_size);
    new_main.bulk_load(main_pairs).await?;
    let new_root = new_main.root_page_id();
    let after_main = new_main.next_page_id();

    let mut new_cat = BTree::open(db.pager.clone(), db.realm_id, 0, after_main, db.page_size);
    new_cat.bulk_load(cat_rows).await?;
    let new_cat_root = new_cat.root_page_id();
    let new_next = new_cat.next_page_id();

    // Pre-size and zero the scratch file so the reserved header/spare pages
    // (0-3, and the unused B header slot) are well-defined.
    {
        let mut f = db.vfs.open(scratch, OpenMode::CreateOrOpen).await?;
        f.set_len(new_next.saturating_mul(db.page_size as u64))
            .await?;
        f.sync().await?;
    }

    // Flush the compacted data pages to the scratch file.
    db.pager.flush_main_to(db.realm_id, scratch).await?;

    // Write the scratch header into slot A (passing B as "previous" so
    // `commit_header` targets A). The anchor is snapshotted after the flush so
    // it covers every nonce the flush consumed.
    let new_commit_id = state.latest_commit_id + 1;
    let new_seq = state.seq + 1;
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
    state.active_slot = ActiveSlot::A;
    state.seq += 1;
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
    use crate::{Db, RealmId};

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
