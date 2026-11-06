//! `compact_now` dropped before and after its rename.

use crate::Db;
use crate::pager::core::FileKey;
use crate::vfs::gated::{GatedVfs, bounded, cancel_when};
use crate::vfs::{OpenMode, Vfs};

use super::support::{
    KEK, PAGE, REALM, assert_every_row_reads_back, next_commit, poisoned_commit, repack_options,
    store_with_free_pages,
};

/// Pages 0-3 are the header slots, so the scratch's first sizing stops here.
const RESERVED_LEN: u64 = 4 * PAGE as u64;

fn dirty_page_count(db: &Db<GatedVfs>) -> usize {
    db.pager
        .inner
        .buffer_pool
        .lock()
        .dirty_for_file(FileKey::Main)
        .len()
}

/// The rename has landed and the directory sync has not run. The published
/// snapshot names old roots over the new file. A dense repack can make an old
/// root id a valid page in that file.
#[tokio::test(flavor = "current_thread")]
async fn compact_dropped_after_the_rename_poisons_and_reopens_with_all_data() {
    let (vfs, db) = store_with_free_pages().await;
    let expected = next_commit(&db);
    let dir_sync = vfs.park_next_sync_dir("/");

    cancel_when(Box::pin(db.compact_now()), dir_sync.wait_until_parked()).await;

    assert_eq!(poisoned_commit(db.begin_read().await), expected);
    assert_eq!(poisoned_commit(db.begin_write().await), expected);
    assert!(db.writer.try_lock().is_ok(), "the writer lock stayed held");
    assert!(
        db.visibility_gate.try_write().is_ok(),
        "the visibility gate stayed held"
    );
    drop(db);

    let reopened = Db::open(vfs.clone(), KEK, PAGE, REALM, repack_options())
        .await
        .unwrap();
    assert_eq!(reopened.latest_commit(), expected);
    assert_every_row_reads_back(&reopened).await;
    assert_eq!(reopened.writer.lock().await.free_list_root_page_id, 0);
}

/// A backend can finish a rename after its future is dropped. A drop at the rename
/// therefore leaves the image unknown. `MemVfs` does not run it, so the old image
/// survives the reopen here.
#[tokio::test(flavor = "current_thread")]
async fn compact_dropped_at_the_rename_poisons_and_reopens_with_all_data() {
    let (vfs, db) = store_with_free_pages().await;
    let expected = next_commit(&db);
    let rename = vfs.park_next_rename(&db.main_db_path);

    cancel_when(Box::pin(db.compact_now()), rename.wait_until_parked()).await;

    assert_eq!(poisoned_commit(db.begin_read().await), expected);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, repack_options())
        .await
        .unwrap();
    assert_every_row_reads_back(&reopened).await;
}

/// The second scratch open is the repack's first budget flush. Its dirty pages
/// carry compacted content under ids the live image uses. The next commit's
/// `flush_main` writes every dirty main page to the live file.
#[tokio::test(flavor = "current_thread")]
async fn compact_dropped_before_the_rename_leaves_the_next_commit_off_the_live_pages() {
    let (vfs, db) = store_with_free_pages().await;
    let scratch = format!("{}.compact", db.main_db_path);
    let sizing = vfs.park_next_open(&scratch);
    let first_flush = vfs.park_next_open(&scratch);

    cancel_when(Box::pin(db.compact_now()), async {
        sizing.wait_until_parked().await;
        sizing.release();
        first_flush.wait_until_parked().await;
        assert!(
            dirty_page_count(&db) > 0,
            "setup error: the repack reached its flush with nothing dirty"
        );
    })
    .await;

    assert_eq!(
        dirty_page_count(&db),
        0,
        "compacted pages stayed dirty, and the next commit writes them to the live file"
    );
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"after-cancel", b"durable").await.unwrap();
    txn.commit().await.unwrap();
    assert_every_row_reads_back(&db).await;
    drop(db);

    let reopened = Db::open(vfs.clone(), KEK, PAGE, REALM, repack_options())
        .await
        .unwrap();
    assert_every_row_reads_back(&reopened).await;
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"after-cancel").await.unwrap().as_deref(),
        Some(b"durable".as_slice())
    );
    assert!(
        vfs.open(&scratch, OpenMode::Read).await.is_err(),
        "the open removes the scratch the dropped repack left"
    );
}

/// A clean compacted page answers a read of its id from the cache. No disk access
/// happens, so no authentication tag can reject it. The final sizing comes after
/// the last source read, so the rebuild's tail is resident.
#[tokio::test(flavor = "current_thread")]
async fn compact_dropped_before_the_rename_keeps_reads_on_the_old_image_and_can_rerun() {
    let (vfs, db) = store_with_free_pages().await;
    let scratch = format!("{}.compact", db.main_db_path);
    let final_sizing = vfs.park_next_truncate_above(&scratch, RESERVED_LEN);

    cancel_when(Box::pin(db.compact_now()), final_sizing.wait_until_parked()).await;

    assert_every_row_reads_back(&db).await;
    let stats = bounded(Box::pin(db.compact_now())).await.unwrap();
    assert!(
        stats.main_db_pages_reclaimed > 0,
        "the rerun did not repack"
    );
    assert_every_row_reads_back(&db).await;
}
