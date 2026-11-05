//! Reads running beside a dense repack.
//!
//! A repack writes compacted pages under page ids the old image also uses. So an
//! old page arriving late lands on a compacted page id.
//!
//! `Db::stats` holds the visibility gate's read side and reads no free-list chain,
//! so it waits for a repack. Each test asserts that wait. Each test then drives
//! the same race through a direct pager read, which has no such hold.
//!
//! The pager holds the main handle mutex across a read. A parked read therefore
//! blocks the repack's next source read, so each test parks the repack on
//! scratch-file work that takes no main handle.

use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::timeout;

use crate::options::{OpenOptions, RetainPolicy};
use crate::pager::core::FileKey;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::gated::{GatedVfs, bounded};
use crate::{Db, PagedbError, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [9u8; 32];
const REALM: RealmId = RealmId::new([0x5C; 16]);
const ROWS: u32 = 300;
const POOL_PAGES: usize = 16;
/// Pages 0-3 are the header slots, so compacted pages start here.
const RESERVED_PAGES: u64 = 4;
/// The repack's first budget flush covers the pages below this id.
const LOWEST_CHAIN_HEAD: u64 = RESERVED_PAGES + POOL_PAGES as u64 + 8;
/// The repack's first 256-row source batch writes at least 256 pages, one
/// overflow page per row, so it covers every id up to this one.
const HIGHEST_CHAIN_HEAD: u64 = 240;
/// A value past the inline threshold that fits in one overflow page.
const VALUE_LEN: usize = 3000;
/// How long a `stats` call runs while a parked repack holds the gate. The repack
/// stays parked until the test releases it, so `stats` cannot finish in any time.
const STATS_PATIENCE: Duration = Duration::from_millis(50);

fn row_key(row: u32) -> Vec<u8> {
    format!("row-{row:05}").into_bytes()
}

fn row_value(row: u32, generation: u8) -> Vec<u8> {
    let mut value = vec![generation; VALUE_LEN];
    value[..4].copy_from_slice(&row.to_le_bytes());
    value
}

fn options() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)
}

struct Store {
    vfs: GatedVfs,
    db: Db<GatedVfs>,
    /// Page id the published free-list root names.
    chain_head: u64,
    generations: Vec<u8>,
}

/// Build a store whose free-chain head has an id the repack's first source batch
/// also writes, so the old chain page and a compacted page share one id.
///
/// The commit path picks the head from already-free pages. Overwriting low rows
/// fills the free list with low ids, and the loop stops once one hosts the chain.
async fn store_with_chain_head_in_the_first_batch() -> Store {
    let vfs = GatedVfs::new();
    let mut generations = vec![0u8; ROWS as usize];
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, options())
        .await
        .unwrap();
    {
        let mut txn = db.begin_write().await.unwrap();
        for row in 0..ROWS {
            txn.put(&row_key(row), &row_value(row, 0)).await.unwrap();
        }
        txn.commit().await.unwrap();
    }
    {
        let mut txn = db.begin_write().await.unwrap();
        for row in 40..60u32 {
            generations[row as usize] = 1;
            txn.put(&row_key(row), &row_value(row, 1)).await.unwrap();
        }
        txn.commit().await.unwrap();
    }
    let mut chain_head = 0;
    for row in 100..132u32 {
        let mut txn = db.begin_write().await.unwrap();
        generations[row as usize] = 1;
        txn.put(&row_key(row), &row_value(row, 1)).await.unwrap();
        txn.commit().await.unwrap();
        let head = db.writer.lock().await.free_list_root_page_id;
        if (LOWEST_CHAIN_HEAD..=HIGHEST_CHAIN_HEAD).contains(&head) {
            chain_head = head;
            break;
        }
    }
    assert_ne!(
        chain_head, 0,
        "setup error: no commit placed the free-chain head in \
         {LOWEST_CHAIN_HEAD}..={HIGHEST_CHAIN_HEAD}, so the scenario did not run"
    );
    drop(db);

    // The small pool makes the repack flush often, which gives its gates places
    // to park inside one source batch.
    let db = Db::open(
        vfs.clone(),
        KEK,
        PAGE,
        REALM,
        options().with_buffer_pool_pages(POOL_PAGES),
    )
    .await
    .unwrap();
    assert_eq!(db.writer.lock().await.free_list_root_page_id, chain_head);
    Store {
        vfs,
        db,
        chain_head,
        generations,
    }
}

fn page_is_dirty(db: &Db<GatedVfs>, page_id: u64) -> bool {
    db.pager
        .inner
        .buffer_pool
        .lock()
        .dirty_for_file(FileKey::Main)
        .contains(&page_id)
}

async fn assert_every_row_reads_back(db: &Db<GatedVfs>, generations: &[u8]) {
    let reader = db.begin_read().await.unwrap();
    for row in 0..ROWS {
        let value = reader
            .get(&row_key(row))
            .await
            .unwrap_or_else(|error| panic!("row {row} is unreadable after compaction: {error:?}"));
        assert_eq!(
            value.as_deref(),
            Some(row_value(row, generations[row as usize]).as_slice()),
            "row {row} has the wrong value after compaction"
        );
    }
}

/// `stats` waits for a running repack and reports the compacted store.
///
/// A read of the old chain page starts before the repack writes that page id. The
/// read finishes while the compacted page is dirty. The old page cannot reach the
/// published image, and the read reports the kind mismatch of a cache hit.
///
/// The gates fix this order:
/// 1. The repack reads its source batch and parks in a budget flush.
/// 2. The read misses the chain head, copies the old bytes, and parks.
/// 3. The repack writes the compacted page and parks in a later flush.
/// 4. The read finishes, and the repack runs to the rename.
#[tokio::test(flavor = "current_thread")]
async fn stats_during_compaction_leaves_the_compacted_image_intact() {
    let Store {
        vfs,
        db,
        chain_head,
        generations,
    } = store_with_chain_head_in_the_first_batch().await;
    let scratch = format!("{}.compact", db.main_db_path);

    // The repack opens its scratch once to size it, then once per budget flush.
    let sizing_open = vfs.park_next_open(&scratch);
    let first_flush = vfs.park_next_open(&scratch);
    let old_chain_read = vfs.park_next_read(&db.main_db_path, chain_head * PAGE as u64);
    let read_finished = Notify::new();

    let compaction = db.compact_now();
    let racing_read = async {
        first_flush.wait_until_parked().await;
        let outcome = db
            .pager
            .read_main_page(chain_head, REALM, PageKind::Free)
            .await
            .map(drop);
        read_finished.notify_one();
        outcome
    };
    let driver = async {
        sizing_open.wait_until_parked().await;
        sizing_open.release();
        first_flush.wait_until_parked().await;
        old_chain_read.wait_until_parked().await;

        assert!(
            timeout(STATS_PATIENCE, db.stats()).await.is_err(),
            "stats finished while the repack held the visibility gate"
        );

        let mut parked = first_flush.clone();
        while !page_is_dirty(&db, chain_head) {
            let next_flush = vfs.park_next_open(&scratch);
            parked.release();
            next_flush.wait_until_parked().await;
            parked = next_flush;
        }

        old_chain_read.release();
        read_finished.notified().await;
        parked.release();
    };
    let (compacted, racing_outcome, ()) =
        bounded(async { tokio::join!(compaction, racing_read, driver) }).await;

    let compacted = compacted.expect("compaction succeeds");
    assert!(!compacted.declined_readers_pinned);
    assert!(
        matches!(racing_outcome, Err(PagedbError::ChecksumFailure)),
        "the resident compacted page is not a free-list page, got: {racing_outcome:?}"
    );
    let stats = db.stats().await.expect("stats reads the compacted store");
    assert_eq!(stats.free_list_pending_entries, 0);
    assert_every_row_reads_back(&db, &generations).await;
}

/// A read of the old image holds the replaced handle across the swap. It finishes
/// after the final cache reset. Its page cannot stay resident and answer later
/// reads of the compacted image.
#[tokio::test(flavor = "current_thread")]
async fn stale_read_after_final_compaction_reset_does_not_stay_resident() {
    let Store {
        vfs,
        db,
        chain_head,
        generations,
    } = store_with_chain_head_in_the_first_batch().await;
    let scratch = format!("{}.compact", db.main_db_path);

    // The sizing above the reserved pages comes after the last source read.
    let final_sizing = vfs.park_next_truncate_above(&scratch, RESERVED_PAGES * PAGE as u64);
    let old_chain_read = vfs.park_next_read(&db.main_db_path, chain_head * PAGE as u64);
    let compaction_finished = Notify::new();

    let compaction = async {
        let outcome = db.compact_now().await;
        compaction_finished.notify_one();
        outcome
    };
    let stale_read = async {
        final_sizing.wait_until_parked().await;
        db.pager
            .read_main_page(chain_head, REALM, PageKind::Free)
            .await
            .map(drop)
    };
    let driver = async {
        final_sizing.wait_until_parked().await;
        old_chain_read.wait_until_parked().await;
        final_sizing.release();
        compaction_finished.notified().await;
        old_chain_read.release();
    };
    let (compacted, stale_outcome, ()) =
        bounded(async { tokio::join!(compaction, stale_read, driver) }).await;

    let compacted = compacted.expect("compaction succeeds");
    assert!(!compacted.declined_readers_pinned);
    stale_outcome.expect("the read returns the old page it fetched");
    assert!(
        chain_head < db.writer.lock().await.next_page_id,
        "setup error: the compacted image does not reach page {chain_head}, \
         so no tree read reaches a stale page"
    );
    let resident_kind = db
        .pager
        .inner
        .buffer_pool
        .lock()
        .get((FileKey::Main, chain_head))
        .unwrap()
        .map(|page| page.kind_byte);
    assert_ne!(
        resident_kind,
        Some(PageKind::Free.as_byte()),
        "the old chain page stayed resident after the swap"
    );
    assert_every_row_reads_back(&db, &generations).await;
}

/// A cache miss between closing the main handle and the rename opens the old
/// inode. That handle cannot stay cached, because later reads and flushes then
/// use the replaced file.
///
/// `MemVfs` models this directly. A rename moves the path to another inode and
/// an open handle keeps its own, as on POSIX.
#[tokio::test(flavor = "current_thread")]
async fn read_during_swap_does_not_cache_the_replaced_file_handle() {
    let Store {
        vfs,
        db,
        generations,
        ..
    } = store_with_chain_head_in_the_first_batch().await;

    let rename = vfs.park_next_rename(&db.main_db_path);
    let compaction = db.compact_now();
    let driver = async {
        rename.wait_until_parked().await;
        assert!(
            timeout(STATS_PATIENCE, db.stats()).await.is_err(),
            "stats finished while the swap held the visibility gate"
        );
        // Clean compacted pages share ids with the old image, so eviction forces
        // the miss that reopens the file. The published root still names the old
        // image, which is the file this read opens.
        db.evict_main_pages(REALM).unwrap();
        let old_root = db.snapshot.read().root_page_id;
        db.pager
            .read_main_node(old_root, REALM)
            .await
            .map(drop)
            .expect("the read reaches the old inode");
        rename.release();
    };
    let (compacted, ()) = bounded(async { tokio::join!(compaction, driver) }).await;

    let compacted = compacted.expect("compaction succeeds");
    assert!(!compacted.declined_readers_pinned);
    assert_every_row_reads_back(&db, &generations).await;

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"after-swap", b"durable").await.unwrap();
    txn.commit().await.unwrap();
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, options()).await.unwrap();
    assert_every_row_reads_back(&reopened, &generations).await;
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"after-swap").await.unwrap().as_deref(),
        Some(b"durable".as_slice()),
        "the commit after the swap reached a file the path no longer names"
    );
}
