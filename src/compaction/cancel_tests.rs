//! `replace_segment_compact` run directly, because a repack that runs first
//! empties the history and free list this path has to preserve.

use crate::catalog::codec::{SegmentKind, SegmentMeta};
use crate::pager::core::FileKey;
use crate::recovery::deep_walk::run_deep_walk;
use crate::segment::types::SegmentPageKind;
use crate::vfs::gated::{GatedVfs, bounded, cancel_when};
use crate::{CommitId, Db, OpenOptions, PagedbError, RealmId};

use super::helpers::replace_segment_compact;

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x7E; 32];
const REALM: RealmId = RealmId::new([0x8F; 16]);
const SEGMENT: &str = "engine.idx";

struct Fixture {
    vfs: GatedVfs,
    db: Db<GatedVfs>,
    old_meta: SegmentMeta,
    new_meta: SegmentMeta,
    first_commit: CommitId,
}

async fn sealed_segment(db: &Db<GatedVfs>, bytes: &[u8]) -> SegmentMeta {
    let mut writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(SegmentPageKind::Data, bytes)
        .await
        .unwrap();
    writer.seal().await.unwrap()
}

/// One commit that links a segment, with a commit-history row. A second sealed
/// segment waits to replace the first.
async fn store_with_linked_segment() -> Fixture {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let old_meta = sealed_segment(&db, b"old-bytes").await;
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"retained", b"first").await.unwrap();
    txn.link_segment(SEGMENT, &old_meta).await.unwrap();
    let first_commit = txn.commit().await.unwrap();
    let new_meta = sealed_segment(&db, b"new-bytes").await;
    Fixture {
        vfs,
        db,
        old_meta,
        new_meta,
        first_commit,
    }
}

async fn replace(fixture: &Fixture) {
    let db = &fixture.db;
    let mut state = db.writer.lock().await;
    let visibility = db.visibility_gate.write().await;
    replace_segment_compact(
        db,
        &mut state,
        &visibility,
        SEGMENT,
        &fixture.old_meta.segment_id,
        &fixture.new_meta,
    )
    .await
    .unwrap();
}

/// A repack that was skipped leaves the commit history live. A header that drops
/// its root disagrees with `state`, and a reopen loses every retained commit.
#[tokio::test(flavor = "current_thread")]
async fn replace_segment_compact_keeps_the_commit_history_in_its_header() {
    let fixture = store_with_linked_segment().await;
    let history_root = fixture.db.writer.lock().await.commit_history_root_page_id;
    assert_ne!(history_root, 0, "setup error: the commit wrote no history");

    replace(&fixture).await;
    let Fixture {
        vfs,
        db,
        first_commit,
        ..
    } = fixture;
    let state_history = db.writer.lock().await.commit_history_root_page_id;
    assert_eq!(state_history, history_root);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(
        reopened.writer.lock().await.commit_history_root_page_id,
        state_history,
        "the durable header disagrees with the state it was written from"
    );
    let historical = reopened.begin_read_at(first_commit).await.unwrap();
    assert_eq!(
        historical.get(b"retained").await.unwrap().as_deref(),
        Some(b"first".as_slice())
    );
}

/// The catalog rewrite supersedes pages. They must join the free list, or no root
/// and no free-list entry names them.
#[tokio::test(flavor = "current_thread")]
async fn replace_segment_compact_puts_the_superseded_catalog_pages_on_the_free_list() {
    let fixture = store_with_linked_segment().await;
    let entries_before = {
        let state = fixture.db.writer.lock().await;
        state.free_list_entries.unwrap_or(0)
    };

    replace(&fixture).await;
    let Fixture { vfs, db, .. } = fixture;
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

/// The new catalog is durable and `state` has not taken it.
#[tokio::test(flavor = "current_thread")]
async fn replace_segment_compact_dropped_after_its_header_write_poisons_the_handle() {
    let fixture = store_with_linked_segment().await;
    let db = &fixture.db;
    let expected = CommitId::new(db.latest_commit().value() + 1);
    let offset = db.pager.header_cursor().unwrap().slot.other().page_id() * PAGE as u64;
    let header = fixture.vfs.park_next_write_at(&db.main_db_path, offset);

    {
        let mut state = db.writer.lock().await;
        let visibility = db.visibility_gate.write().await;
        cancel_when(
            Box::pin(replace_segment_compact(
                db,
                &mut state,
                &visibility,
                SEGMENT,
                &fixture.old_meta.segment_id,
                &fixture.new_meta,
            )),
            header.wait_until_parked(),
        )
        .await;
    }

    assert!(matches!(
        db.begin_read().await,
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) if commit == expected
    ));
    let Fixture { vfs, db, .. } = fixture;
    drop(db);

    let reopened = bounded(Box::pin(Db::open(
        vfs,
        KEK,
        PAGE,
        REALM,
        OpenOptions::default(),
    )))
    .await
    .unwrap();
    let segment = reopened.open_segment(REALM, SEGMENT).await.unwrap();
    assert!(
        segment
            .read_page(1)
            .await
            .unwrap()
            .starts_with(b"new-bytes")
    );
}

/// The catalog flush runs before any header. A drop there leaves the old catalog
/// durable, so it must discard the staged pages and must not poison.
#[tokio::test(flavor = "current_thread")]
async fn replace_segment_compact_dropped_before_its_header_write_leaves_nothing_staged() {
    let fixture = store_with_linked_segment().await;
    let db = &fixture.db;
    let flush_sync = fixture.vfs.park_next_sync(&db.main_db_path);

    {
        let mut state = db.writer.lock().await;
        let visibility = db.visibility_gate.write().await;
        cancel_when(
            Box::pin(replace_segment_compact(
                db,
                &mut state,
                &visibility,
                SEGMENT,
                &fixture.old_meta.segment_id,
                &fixture.new_meta,
            )),
            flush_sync.wait_until_parked(),
        )
        .await;
    }

    db.ensure_usable().unwrap();
    let dirty = db
        .pager
        .inner
        .buffer_pool
        .lock()
        .dirty_for_file(FileKey::Main);
    assert_eq!(dirty, Vec::<u64>::new(), "staged pages stayed dirty");
    let segment = db.open_segment(REALM, SEGMENT).await.unwrap();
    assert!(
        segment
            .read_page(1)
            .await
            .unwrap()
            .starts_with(b"old-bytes")
    );
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"after-cancel", b"value").await.unwrap();
    txn.commit().await.unwrap();
}
