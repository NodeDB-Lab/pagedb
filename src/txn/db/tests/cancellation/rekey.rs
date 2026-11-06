//! `rekey_db` dropped before and inside its durable window.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::timeout;

use crate::options::OpenOptions;
use crate::pager::core::FileKey;
use crate::vfs::gated::{GatedVfs, cancel_when};
use crate::vfs::{OpenMode, Vfs, VfsFile};
use crate::{Db, PagedbError};

use super::support::{KEK, PAGE, REALM, next_header_offset, poisoned_commit};

const SCRATCH: &str = "/main.db.rekey";
const FIRST_TARGET: [u8; 32] = [0x7A; 32];
const SECOND_TARGET: [u8; 32] = [0x7B; 32];

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

/// The pages of `main.db` from `first_page` up to `pages`.
async fn raw_pages(vfs: &GatedVfs, first_page: u64, pages: u64) -> Vec<u8> {
    let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    let mut bytes = vec![0u8; usize::try_from(pages - first_page).unwrap() * PAGE];
    let read = file
        .read_at(first_page * PAGE as u64, &mut bytes)
        .await
        .unwrap();
    assert_eq!(read, bytes.len());
    bytes
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

/// The live file and `state` still agree, because the rebuild writes only to its
/// scratch. So the handle stays usable. It seals under the source key again, and
/// holds no target key or scratch page. The durable intent makes the next open
/// finish the rekey, and commits made in between survive that.
#[tokio::test(flavor = "current_thread")]
async fn rekey_dropped_during_its_rebuild_leaves_the_handle_usable_and_a_reopen_finishes_it() {
    let (vfs, db) = store_with_a_free_list().await;
    let pages_before = {
        let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
        file.len().await.unwrap() / PAGE as u64
    };
    let live_before = raw_pages(&vfs, 4, pages_before).await;
    let gate = vfs.park_write_number(SCRATCH, 0);

    cancel_when(Box::pin(db.rekey_db(KEK, 1)), gate.wait_until_parked()).await;

    db.ensure_usable().unwrap();
    assert_eq!(db.mk_epoch.load(Ordering::SeqCst), 0);
    assert_eq!(db.pager.active_mk_epoch(), 0);
    assert!(db.pager.mk_for(1, db.cipher_id).is_err());
    assert_eq!(
        db.pager
            .inner
            .buffer_pool
            .lock()
            .dirty_for_file(FileKey::Main),
        Vec::<u64>::new(),
        "a scratch page stayed dirty, so the next flush writes it to the live file"
    );
    assert_eq!(
        raw_pages(&vfs, 4, pages_before).await,
        live_before,
        "no page the rebuild sealed reached the live file"
    );

    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"rekeyed-000").await.unwrap().as_deref(),
        Some([2u8; 64].as_slice())
    );
    drop(reader);
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"after-cancel", b"value").await.unwrap();
    txn.commit().await.unwrap();
    drop(db);

    assert_reopen_finishes_the_rekey(vfs.clone()).await;
    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"after-cancel").await.unwrap().as_deref(),
        Some(b"value".as_slice())
    );
}

/// The same handle can run the rekey again under another key, with a commit in
/// between. Every page was under the source key, so the new run replaces the old
/// intent and no trace of the first key remains. Only the second key opens the store.
#[tokio::test(flavor = "current_thread")]
async fn a_second_rekey_after_a_dropped_rebuild_seals_under_its_own_key_and_a_reopen_needs_only_it()
{
    let (vfs, db) = store_with_a_free_list().await;
    let gate = vfs.park_write_number(SCRATCH, 0);
    cancel_when(
        Box::pin(db.rekey_db(FIRST_TARGET, 1)),
        gate.wait_until_parked(),
    )
    .await;

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"between-attempts", b"value").await.unwrap();
    txn.commit().await.unwrap();

    db.rekey_db(SECOND_TARGET, 1).await.unwrap();

    assert_eq!(db.mk_epoch.load(Ordering::SeqCst), 1);
    assert!(vfs.open(SCRATCH, OpenMode::Read).await.is_err());
    let report = crate::recovery::deep_walk::run_deep_walk(&db)
        .await
        .unwrap();
    assert!(report.is_clean(), "deep walk report: {report:?}");
    drop(db);

    assert!(
        Db::open_existing(vfs.clone(), FIRST_TARGET, PAGE, REALM)
            .await
            .is_err(),
        "the first attempt's key must open nothing"
    );
    let reopened = Db::open_existing(vfs, SECOND_TARGET, PAGE, REALM)
        .await
        .unwrap();
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"between-attempts").await.unwrap().as_deref(),
        Some(b"value".as_slice())
    );
    assert_eq!(
        reader.get(b"rekeyed-000").await.unwrap().as_deref(),
        Some([2u8; 64].as_slice())
    );
    drop(reader);
    let report = crate::recovery::deep_walk::run_deep_walk(&reopened)
        .await
        .unwrap();
    assert!(report.is_clean(), "deep walk report: {report:?}");
}

/// Assert no page holds the target epoch. A seal under it behind a source header
/// makes the intent unreadable at the next open.
async fn assert_no_page_under_the_target_epoch(vfs: &GatedVfs) {
    let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    let pages = file.len().await.unwrap() / PAGE as u64;
    let mut envelope = [0u8; 12];
    for page_id in 4..pages {
        file.read_at(page_id * PAGE as u64, &mut envelope)
            .await
            .unwrap();
        assert_ne!(
            u64::from_le_bytes(envelope[4..12].try_into().unwrap()),
            1,
            "page {page_id} sealed under the target key behind a source header"
        );
    }
}

/// The work a handle can do after a dropped rekey.
#[derive(Clone, Copy, Debug)]
enum AfterCancel {
    LinkSegment,
    SetRealmQuotas,
    CompactNow,
    ConcurrentSegmentWriter,
}

const AFTER_CANCEL: [AfterCancel; 4] = [
    AfterCancel::LinkSegment,
    AfterCancel::SetRealmQuotas,
    AfterCancel::CompactNow,
    AfterCancel::ConcurrentSegmentWriter,
];

async fn sealed_segment(db: &Db<GatedVfs>) -> crate::SegmentMeta {
    let mut writer = db
        .create_segment(REALM, crate::SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(crate::SegmentPageKind::Data, b"after-cancel")
        .await
        .unwrap();
    writer.seal().await.unwrap()
}

async fn link(db: &Db<GatedVfs>, meta: &crate::SegmentMeta) {
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("after-cancel", meta).await.unwrap();
    txn.commit().await.unwrap();
}

async fn assert_after_cancel_work_survived(db: &Db<GatedVfs>, work: AfterCancel) {
    match work {
        AfterCancel::LinkSegment | AfterCancel::ConcurrentSegmentWriter => {
            let segment = db.open_segment(REALM, "after-cancel").await.unwrap();
            assert!(
                segment
                    .read_page(1)
                    .await
                    .unwrap()
                    .starts_with(b"after-cancel"),
                "{work:?}"
            );
        }
        AfterCancel::SetRealmQuotas => {
            assert_eq!(
                db.realm_quotas(REALM).await.unwrap().max_pages,
                Some(1 << 20)
            );
        }
        AfterCancel::CompactNow => {}
    }
    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"rekeyed-000").await.unwrap().as_deref(),
        Some([2u8; 64].as_slice()),
        "{work:?}"
    );
    drop(reader);
    let report = crate::recovery::deep_walk::run_deep_walk(db).await.unwrap();
    assert!(report.is_clean(), "{work:?}: deep walk report: {report:?}");
}

/// Each of these seals pages after the cancel. Under the target key behind a source
/// header, the next open cannot read the intent that installs that key. So each
/// runs, then the store reopens both ways: finishing the rekey, and withdrawing it.
#[tokio::test(flavor = "current_thread")]
async fn store_work_after_a_dropped_rekey_seals_under_the_source_key_and_every_reopen_reads_it() {
    for work in AFTER_CANCEL {
        for finish_on_reopen in [true, false] {
            let (vfs, db) = store_with_a_free_list().await;
            let mut early_writer = db
                .create_segment(REALM, crate::SegmentKind::Unspecified)
                .await
                .unwrap();
            let gate = vfs.park_write_number(SCRATCH, 0);
            cancel_when(
                Box::pin(db.rekey_db(FIRST_TARGET, 1)),
                gate.wait_until_parked(),
            )
            .await;
            db.ensure_usable().unwrap();

            match work {
                AfterCancel::LinkSegment => {
                    let meta = sealed_segment(&db).await;
                    link(&db, &meta).await;
                }
                AfterCancel::SetRealmQuotas => {
                    db.set_realm_quotas(
                        REALM,
                        crate::RealmQuotas::default().with_max_pages(1 << 20),
                    )
                    .await
                    .unwrap();
                }
                AfterCancel::CompactNow => {
                    db.compact_now().await.unwrap();
                }
                AfterCancel::ConcurrentSegmentWriter => {
                    early_writer
                        .append_page(crate::SegmentPageKind::Data, b"after-cancel")
                        .await
                        .unwrap();
                    let meta = early_writer.seal().await.unwrap();
                    assert_eq!(meta.mk_epoch, 0, "{work:?}");
                    link(&db, &meta).await;
                    early_writer = db
                        .create_segment(REALM, crate::SegmentKind::Unspecified)
                        .await
                        .unwrap();
                }
            }
            drop(early_writer);
            assert_no_page_under_the_target_epoch(&vfs).await;
            drop(db);

            let reopened = if finish_on_reopen {
                Db::open_existing_with_counterpart_kek(
                    vfs,
                    KEK,
                    FIRST_TARGET,
                    PAGE,
                    REALM,
                    OpenOptions::default(),
                )
                .await
            } else {
                Db::open_existing(vfs, KEK, PAGE, REALM).await
            }
            .unwrap_or_else(|error| panic!("{work:?} {finish_on_reopen}: {error:?}"));
            assert_eq!(
                reopened.mk_epoch.load(Ordering::SeqCst),
                u64::from(finish_on_reopen),
                "{work:?}"
            );
            assert_after_cancel_work_survived(&reopened, work).await;
        }
    }
}

/// A reader of the gate keeps the rekey parked right before its rename, with the
/// scratch complete. This drop runs with no publish guard armed, so it must find
/// nothing to undo. The flush epoch never left the source.
#[tokio::test(flavor = "current_thread")]
async fn rekey_dropped_while_waiting_for_the_visibility_gate_leaves_the_handle_on_the_source_key() {
    let (vfs, db) = store_with_a_free_list().await;
    let hook = std::sync::Arc::new(crate::txn::db::VisibilityTestHook::default());
    let scratch_header = vfs.park_next_write_at(SCRATCH, 0);
    let rename = vfs.park_next_rename(&db.main_db_path);
    let mut held = None;

    cancel_when(Box::pin(db.rekey_db(FIRST_TARGET, 1)), async {
        scratch_header.wait_until_parked().await;
        db.install_visibility_test_hook(hook.clone());
        held = Some(db.visibility_gate.read().await);
        scratch_header.release();
        hook.writer_waiting.notified().await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    drop(held);
    db.clear_visibility_test_hook();
    drop(rename);

    db.ensure_usable().unwrap();
    assert_eq!(db.mk_epoch.load(Ordering::SeqCst), 0);
    assert_eq!(db.pager.active_mk_epoch(), 0);
    assert!(db.pager.mk_for(1, db.cipher_id).is_err());
    let meta = sealed_segment(&db).await;
    assert_eq!(meta.mk_epoch, 0);
    link(&db, &meta).await;
    db.set_realm_quotas(REALM, crate::RealmQuotas::default().with_max_pages(1 << 20))
        .await
        .unwrap();
    assert_no_page_under_the_target_epoch(&vfs).await;
    drop(db);

    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    assert_eq!(reopened.mk_epoch.load(Ordering::SeqCst), 0);
    assert_after_cancel_work_survived(&reopened, AfterCancel::LinkSegment).await;
}

/// A snapshot of a catalog with an intent row opens nowhere, so the export refuses
/// it until the rekey finishes.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn exports_refuse_a_dropped_rekeys_durable_intent_with_a_typed_error() {
    let (vfs, db) = store_with_a_free_list().await;
    let base = db.latest_commit();
    let gate = vfs.park_write_number(SCRATCH, 0);
    cancel_when(Box::pin(db.rekey_db(KEK, 1)), gate.wait_until_parked()).await;

    for outcome in [
        db.snapshot_to(std::path::Path::new("/unused"))
            .await
            .map(drop),
        db.snapshot_incremental_to(base, std::path::Path::new("/unused"))
            .await
            .map(drop),
    ] {
        assert!(
            matches!(
                outcome,
                Err(PagedbError::RekeyPending {
                    source_epoch: 0,
                    target_epoch: 1
                })
            ),
            "got {outcome:?}"
        );
    }
}

/// A backend can finish the rename after its future drops, so only a reopen can
/// read which file won.
#[tokio::test(flavor = "current_thread")]
async fn rekey_dropped_at_its_rename_poisons_and_resumes_on_reopen() {
    let (vfs, db) = store_with_a_free_list().await;
    let latest = db.latest_commit();
    let rename = vfs.park_next_rename(&db.main_db_path);

    cancel_when(Box::pin(db.rekey_db(KEK, 1)), rename.wait_until_parked()).await;

    assert_eq!(poisoned_commit(db.begin_write().await), latest);
    drop(db);

    assert_reopen_finishes_the_rekey(vfs).await;
}

/// The rename landed. The reopen continues from the scratch's own header and
/// intent, and rebuilds nothing.
#[tokio::test(flavor = "current_thread")]
async fn rekey_dropped_after_its_rename_poisons_and_continues_from_the_new_file() {
    let (vfs, db) = store_with_a_free_list().await;
    let latest = db.latest_commit();
    let dir_sync = vfs.park_next_sync_dir("/");
    let rename = vfs.park_next_rename(&db.main_db_path);

    cancel_when(Box::pin(db.rekey_db(KEK, 1)), async {
        rename.wait_until_parked().await;
        rename.release();
        dir_sync.wait_until_parked().await;
    })
    .await;

    assert_eq!(poisoned_commit(db.begin_write().await), latest);
    drop(db);
    assert!(vfs.open(SCRATCH, OpenMode::Read).await.is_err());

    assert_reopen_finishes_the_rekey(vfs).await;
}

/// The rename reported an error, and the file it left is unknown. The handle
/// poisons, and the reopen finds the old file and starts over.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_rekey_rename_poisons_and_a_reopen_finishes_the_rekey() {
    let (vfs, db) = store_with_a_free_list().await;
    let latest = db.latest_commit();
    vfs.fail_next_rename(&db.main_db_path);

    let error = db.rekey_db(KEK, 1).await.unwrap_err();

    assert!(
        matches!(
            error,
            PagedbError::RekeyTargetEpochActivated { commit, .. } if commit == latest
        ),
        "got {error:?}"
    );
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
