//! `rekey_db` dropped before and inside its durable window.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::timeout;

use crate::options::OpenOptions;
use crate::vfs::gated::{GatedVfs, cancel_when};
use crate::{Db, PagedbError};

use super::support::{KEK, PAGE, REALM, next_header_offset, poisoned_commit};

async fn store_with_a_free_list() -> (GatedVfs, Db<GatedVfs>) {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    for generation in 0..3u8 {
        let mut txn = db.begin_write().await.unwrap();
        for row in 0..20u32 {
            let key = format!("rekeyed-{row:03}");
            txn.put(key.as_bytes(), &[generation; 64]).await.unwrap();
        }
        txn.commit().await.unwrap();
    }
    assert_ne!(
        db.writer.lock().await.free_list_root_page_id,
        0,
        "setup error: the free list is empty, so the rewrite never opens main.db"
    );
    (vfs, db)
}

async fn assert_reopen_finishes_the_rekey(vfs: GatedVfs) {
    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    assert_eq!(reopened.mk_epoch.load(Ordering::SeqCst), 1);
    assert!(
        matches!(
            reopened.pager.mk_for(0, reopened.cipher_id),
            Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
        ),
        "a resumed rekey retires the source epoch"
    );
    let reader = reopened.begin_read().await.unwrap();
    for row in 0..20u32 {
        let key = format!("rekeyed-{row:03}");
        assert_eq!(
            reader.get(key.as_bytes()).await.unwrap().as_deref(),
            Some([2u8; 64].as_slice()),
            "row {row} after the resume"
        );
    }
}

/// The intent header landed. `state` has not taken its catalog root. A later
/// commit then drops the intent row that recovery depends on.
#[tokio::test(flavor = "current_thread")]
async fn rekey_dropped_after_its_intent_header_poisons_and_resumes_on_reopen() {
    let (vfs, db) = store_with_a_free_list().await;
    let latest = db.latest_commit();
    let header = vfs.park_next_write_at(&db.main_db_path, next_header_offset(&db));

    cancel_when(Box::pin(db.rekey_db(KEK, 1)), header.wait_until_parked()).await;

    assert_eq!(poisoned_commit(db.begin_write().await), latest);
    assert_eq!(poisoned_commit(db.begin_read().await), latest);
    drop(db);

    assert_reopen_finishes_the_rekey(vfs).await;
}

/// The first open is the intent's header write. The second is the free-list
/// rewrite, which runs with target-epoch pages dirty in the cache.
#[tokio::test(flavor = "current_thread")]
async fn rekey_dropped_during_its_page_rewrite_poisons_and_resumes_on_reopen() {
    let (vfs, db) = store_with_a_free_list().await;
    let latest = db.latest_commit();
    let intent_header = vfs.park_next_open(&db.main_db_path);
    let free_list_rewrite = vfs.park_next_open(&db.main_db_path);

    cancel_when(Box::pin(db.rekey_db(KEK, 1)), async {
        intent_header.wait_until_parked().await;
        intent_header.release();
        free_list_rewrite.wait_until_parked().await;
    })
    .await;

    assert_eq!(poisoned_commit(db.begin_write().await), latest);
    drop(db);

    assert_reopen_finishes_the_rekey(vfs).await;
}

/// No intent exists while the call waits for the writer lock, so a drop there
/// changes nothing.
#[tokio::test(flavor = "current_thread")]
async fn rekey_dropped_while_waiting_for_the_writer_lock_leaves_the_handle_usable() {
    let (_vfs, db) = store_with_a_free_list().await;
    let held = db.writer.lock().await;
    assert!(
        timeout(Duration::from_millis(50), Box::pin(db.rekey_db(KEK, 1)))
            .await
            .is_err(),
        "the rekey finished while the test held the writer lock"
    );
    drop(held);

    db.ensure_usable().unwrap();
    assert_eq!(db.mk_epoch.load(Ordering::SeqCst), 0);
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"after-cancel", b"value").await.unwrap();
    txn.commit().await.unwrap();
}
