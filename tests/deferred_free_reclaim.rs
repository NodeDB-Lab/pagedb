//! Deferred-free reclamation on the commit path.
//!
//! When no reader pins an old snapshot, pages freed by a commit are eligible
//! for immediate reuse. A store that rewrites a bounded working set over many
//! one-commit-per-write transactions must therefore stay bounded in both
//! file size and deferred-free backlog depth — the freed pages have to flow
//! back to the allocator instead of accumulating in the deferred-free queue.
//!
//! These tests pin the *bounded* contract: they rewrite a constant key set
//! across a growing number of commits and assert that neither the file's
//! high-water mark nor the deferred-free backlog grows in proportion to the
//! commit count.

use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};

const KEK: [u8; 32] = [0x2Au8; 32];
const REALM: RealmId = RealmId::new([0x5Cu8; 16]);
const PAGE: usize = 4096;

/// A constant working set: the same keys rewritten every round so that the
/// live data size never changes — only the commit count does.
const LIVE_KEYS: u32 = 20;
const VALUE: [u8; 256] = [0xABu8; 256];

/// These tests isolate free-page *reuse*, so commit history is disabled: a
/// retained historical root legitimately pins the pages of every prior commit
/// (that's the point of retention), which would mask reclamation. Reclamation
/// under a *bounded* history window is covered separately by
/// [`bounded_history_reuses_pages_after_window`].
fn no_history_opts() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)
}

async fn fresh_db() -> Db<MemVfs> {
    Db::open_internal_with_options(MemVfs::new(), KEK, PAGE, REALM, no_history_opts())
        .await
        .unwrap()
}

/// Rewrite the whole working set in one transaction, one commit per round.
async fn overwrite_round(db: &Db<MemVfs>, round: u32) {
    let mut w = db.begin_write().await.unwrap();
    for i in 0..LIVE_KEYS {
        let mut v = VALUE;
        v[0] = (round % 251) as u8;
        w.put(format!("k{i:04}").as_bytes(), &v).await.unwrap();
    }
    w.commit().await.unwrap();
}

/// With no readers pinning, the deferred-free backlog must not accumulate in
/// proportion to the number of commits: eligible freed pages drain back to the
/// allocator on commit. A constant working set rewritten N times should leave
/// only a bounded backlog, not one that scales with N.
#[tokio::test(flavor = "current_thread")]
async fn sustained_overwrite_commits_drain_deferred_free() {
    let db = fresh_db().await;

    // Seed the working set.
    overwrite_round(&db, 0).await;

    // No reader is ever opened, so every freed page is immediately eligible
    // for reuse. Run enough rounds that an un-drained queue would be obvious.
    for round in 1..=200 {
        overwrite_round(&db, round).await;
    }

    let stats = db.stats().await.unwrap();
    assert!(
        stats.free_list_pending_entries < 64,
        "deferred-free backlog must stay bounded when no readers pin — it must \
         drain on commit, not accumulate one entry per freed page; after 200 \
         commits of a {LIVE_KEYS}-key working set the backlog was {} entries",
        stats.free_list_pending_entries,
    );
}

/// Rewriting a constant working set must reuse freed pages, so the file's
/// high-water mark (`next_page_id`) stays bounded regardless of how many
/// commits were issued. Today the allocator only bump-allocates across
/// commits, so `next_page_id` grows linearly with the commit count.
#[tokio::test(flavor = "current_thread")]
async fn sustained_overwrite_commits_keep_file_bounded() {
    let db = fresh_db().await;

    overwrite_round(&db, 0).await;

    for round in 1..=200 {
        overwrite_round(&db, round).await;
    }

    let stats = db.stats().await.unwrap();
    // The working set is ~20 keys × 256 B; the entire live tree fits in a
    // double-digit page count. The bound here is a constant — it must NOT
    // scale with the 200 commits issued.
    assert!(
        stats.main_db_next_page_id < 200,
        "file high-water mark must stay bounded for a constant working set; \
         after 200 one-commit-per-write rounds next_page_id was {} (linear \
         growth means freed pages were never reused)",
        stats.main_db_next_page_id,
    );
}

/// The bound must hold independent of commit count: doubling the number of
/// commits over the same working set must not roughly double the file size.
/// This is the direct guard against the super-linear growth reported.
#[tokio::test(flavor = "current_thread")]
async fn file_growth_is_independent_of_commit_count() {
    let measure = |rounds: u32| async move {
        let db = fresh_db().await;
        overwrite_round(&db, 0).await;
        for round in 1..=rounds {
            overwrite_round(&db, round).await;
        }
        db.stats().await.unwrap().main_db_next_page_id
    };

    let at_100 = measure(100).await;
    let at_400 = measure(400).await;

    // 4× the commits over the same data must not meaningfully grow the file.
    assert!(
        at_400 <= at_100 + 16,
        "file size scales with commit count (super-linear growth): \
         next_page_id was {at_100} after 100 commits and {at_400} after 400 \
         commits of the same {LIVE_KEYS}-key working set",
    );
}

/// With a *bounded* commit-history window, pages reachable only from commits
/// older than the window become reclaimable once those commits are pruned, so
/// sustained writes stay bounded a constant factor above the window size —
/// they do not grow without bound the way the unbounded deferred-free queue
/// did. This is the reported default-configuration daemon scenario.
#[tokio::test(flavor = "current_thread")]
async fn bounded_history_reuses_pages_after_window() {
    const WINDOW: u32 = 8;
    let opts = OpenOptions::default().with_commit_history_retain(RetainPolicy::Count(WINDOW));
    let db = Db::open_internal_with_options(MemVfs::new(), KEK, PAGE, REALM, opts)
        .await
        .unwrap();

    overwrite_round(&db, 0).await;
    for round in 1..=300 {
        overwrite_round(&db, round).await;
    }

    let stats = db.stats().await.unwrap();
    // Live working set + a bounded history window of CoW deltas + the bounded
    // deferred-free queue that holds the window's not-yet-prunable frees. This
    // is a small constant — emphatically not the ~900 pages 300 unreclaimed
    // commits would produce.
    assert!(
        stats.main_db_next_page_id < 200,
        "bounded history must keep the file bounded; after 300 commits with a \
         {WINDOW}-commit window next_page_id was {}",
        stats.main_db_next_page_id,
    );
}

/// The free list is durable: pages freed before an *unclean* shutdown (no
/// compaction, no graceful drain) are recovered on reopen and recycled, so the
/// file does not grow when the freed space is re-used after a restart. This is
/// the crash-durability guarantee — under an in-memory-only free pool those
/// pages would be orphaned until a compaction.
#[tokio::test(flavor = "current_thread")]
async fn free_list_survives_unclean_reopen() {
    let vfs = MemVfs::new();

    // Write a working set, then delete it — freeing many pages into the durable
    // free list — and drop the handle without compacting or draining.
    let high_water_before;
    {
        let db = Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, no_history_opts())
            .await
            .unwrap();
        {
            let mut w = db.begin_write().await.unwrap();
            for i in 0u32..400 {
                w.put(format!("k{i:05}").as_bytes(), &VALUE).await.unwrap();
            }
            w.commit().await.unwrap();
        }
        {
            let mut w = db.begin_write().await.unwrap();
            for i in 0u32..400 {
                w.delete(format!("k{i:05}").as_bytes()).await.unwrap();
            }
            w.commit().await.unwrap();
        }
        high_water_before = db.stats().await.unwrap().main_db_next_page_id;
        let pending = db.stats().await.unwrap().free_list_pending_entries;
        assert!(
            pending > 20,
            "deletes should have freed pages into the durable free list; got {pending}"
        );
        // Drop without compaction or graceful shutdown — simulates a crash.
    }

    // Reopen and write a fresh working set. With the free list recovered from
    // disk, these allocations recycle the freed pages instead of extending the
    // file past where it already was.
    let db = Db::open_existing_with_options(vfs.clone(), KEK, PAGE, REALM, no_history_opts())
        .await
        .unwrap();
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..400 {
            w.put(format!("n{i:05}").as_bytes(), &VALUE).await.unwrap();
        }
        w.commit().await.unwrap();
    }
    let high_water_after = db.stats().await.unwrap().main_db_next_page_id;
    assert!(
        high_water_after <= high_water_before + 8,
        "freed pages must be recovered from the durable free list and recycled \
         after an unclean reopen; high-water was {high_water_before} before the \
         crash and {high_water_after} after rewriting the same volume"
    );
}
