//! `set_realm_quotas` and `gc_now` dropped mid-run.

use crate::Db;
use crate::catalog::codec::{RealmQuotas, SegmentKind};
use crate::options::OpenOptions;
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
