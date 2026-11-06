//! `set_realm_quotas` and `gc_now` dropped mid-run.

use crate::Db;
use crate::catalog::codec::{RealmQuotas, SegmentKind};
use crate::options::OpenOptions;
use crate::recovery::deep_walk::run_deep_walk;
use crate::segment::types::SegmentPageKind;
use crate::segment::writer::live_path;
use crate::vfs::gated::{GatedVfs, cancel_when};

use super::support::{KEK, PAGE, REALM, next_header_offset, poisoned_commit};

#[tokio::test(flavor = "current_thread")]
async fn realm_quota_update_dropped_after_its_header_write_poisons_the_handle() {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let latest = db.latest_commit();
    let header = vfs.park_next_write_at(&db.main_db_path, next_header_offset(&db));

    cancel_when(
        Box::pin(db.set_realm_quotas(REALM, RealmQuotas::default())),
        header.wait_until_parked(),
    )
    .await;

    assert_eq!(poisoned_commit(db.begin_write().await), latest);
    drop(db);
    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    reopened.realm_quotas(REALM).await.unwrap();
}

/// The catalog rewrite supersedes pages. They must join the free list, or no root
/// and no free-list entry names them.
#[tokio::test(flavor = "current_thread")]
async fn realm_quota_update_puts_the_superseded_catalog_pages_on_the_free_list() {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"base", b"row").await.unwrap();
    txn.commit().await.unwrap();
    db.set_realm_quotas(REALM, RealmQuotas::default())
        .await
        .unwrap();
    let entries_before = db.writer.lock().await.free_list_entries.unwrap_or(0);

    db.set_realm_quotas(REALM, RealmQuotas::default())
        .await
        .unwrap();

    let (entries_after, free_list_root) = {
        let state = db.writer.lock().await;
        (
            state.free_list_entries.unwrap_or(0),
            state.free_list_root_page_id,
        )
    };
    assert!(
        entries_after > entries_before,
        "the free list went from {entries_before} to {entries_after} entries"
    );
    assert_eq!(
        db.stats().await.unwrap().free_list_pending_entries,
        entries_after,
        "the published snapshot disagrees with the writer state"
    );
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(
        reopened.writer.lock().await.free_list_root_page_id,
        free_list_root,
        "the durable header disagrees with the state it was written from"
    );
    let report = run_deep_walk(&reopened).await.unwrap();
    assert!(report.is_clean(), "the reopened store: {report:?}");
}

/// The queue is the only record that a retired file still needs reclaiming. The
/// drain holds an entry off the queue while it works on it.
#[tokio::test(flavor = "current_thread")]
async fn gc_dropped_mid_drain_keeps_the_deferred_tombstone_queued() {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let mut writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(SegmentPageKind::Data, b"retired")
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("retired", &meta).await.unwrap();
    txn.commit().await.unwrap();

    let pinning_reader = db.begin_read().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.unlink_segment("retired").await.unwrap();
    txn.commit().await.unwrap();
    drop(pinning_reader);
    assert_eq!(
        db.pending_tombstones.lock().len(),
        1,
        "setup error: the pinned reader did not defer the tombstone"
    );

    let measure = vfs.park_next_open(&live_path(&meta.segment_id));
    cancel_when(Box::pin(db.gc_now()), measure.wait_until_parked()).await;

    assert_eq!(
        db.pending_tombstones.lock().len(),
        1,
        "the dropped drain lost the record of the retired file"
    );
    db.ensure_usable().unwrap();
    assert_eq!(db.gc_now().await.unwrap().reclaimed_segments, 1);
    assert_eq!(db.pending_tombstones.lock().len(), 0);
}
