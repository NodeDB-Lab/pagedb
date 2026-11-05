// SPDX-License-Identifier: Apache-2.0

//! Dirty pages another writer owns survive the parts of an apply that run
//! outside the writer lock.
//!
//! No public follower path holds dirty main pages while an apply runs. These
//! tests stand in for such a writer by holding the lock and sealing a page.

use tempfile::TempDir;

use crate::pager::PageKind;
use crate::pager::format::data_page::body_capacity;
use crate::snapshot::apply::staged_image_path;
use crate::vfs::tokio_backend::TokioVfs;
use crate::{Db, OpenOptions, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x5C; 32];
const REALM: RealmId = RealmId::new([0x5D; 16]);
const DIRTY_MARKER: u8 = 0xAB;

struct Fixture {
    follower: Db<TokioVfs>,
    delta_dir: TempDir,
    _dirs: [TempDir; 3],
}

fn tempdir() -> TempDir {
    tempfile::tempdir().unwrap()
}

/// A follower at its base commit, and a valid delta to the next commit.
async fn follower_with_delta() -> Fixture {
    let src_dir = tempdir();
    let snap_dir = tempdir();
    let dst_dir = tempdir();
    let delta_dir = tempdir();

    let source = Db::open(
        TokioVfs::new(src_dir.path()),
        KEK,
        PAGE,
        REALM,
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let mut write = source.begin_write().await.unwrap();
    write.put(b"base", b"value").await.unwrap();
    let base = write.commit().await.unwrap();
    source.snapshot_to(snap_dir.path()).await.unwrap();
    let mut write = source.begin_write().await.unwrap();
    write.put(b"target", b"value").await.unwrap();
    write.commit().await.unwrap();
    source
        .snapshot_incremental_to(base, delta_dir.path())
        .await
        .unwrap();
    drop(source);

    let follower =
        Db::<TokioVfs>::restore_from(snap_dir.path(), dst_dir.path(), OpenOptions::default(), KEK)
            .await
            .unwrap()
            .promote_to_follower()
            .await
            .unwrap();
    Fixture {
        follower,
        delta_dir,
        _dirs: [src_dir, snap_dir, dst_dir],
    }
}

/// Seal a page past the end of the file, so only the cache can serve it.
async fn write_dirty_page(follower: &Db<TokioVfs>, next_page_id: u64) -> u64 {
    let page_id = next_page_id + 1_000;
    follower
        .pager
        .write_main_page(
            page_id,
            REALM,
            PageKind::Free,
            &vec![DIRTY_MARKER; body_capacity(PAGE)],
        )
        .await
        .unwrap();
    page_id
}

async fn assert_dirty_page_resident(follower: &Db<TokioVfs>, page_id: u64) {
    let guard = follower
        .pager
        .read_main_page(page_id, REALM, PageKind::Free)
        .await
        .expect("the other writer's dirty page stays in the cache");
    assert_eq!(guard.body_ref()[0], DIRTY_MARKER);
}

#[tokio::test(flavor = "current_thread")]
async fn preparing_an_apply_keeps_another_writers_dirty_page() {
    let fixture = follower_with_delta().await;
    let follower = &fixture.follower;
    let other_writer = follower.writer.lock().await;
    let page_id = write_dirty_page(follower, other_writer.next_page_id).await;

    let staged_image = staged_image_path(&follower.main_db_path);
    let prepared = follower
        .prepare_incremental_target(fixture.delta_dir.path(), &staged_image)
        .await
        .unwrap();
    drop(prepared);

    assert_dirty_page_resident(follower, page_id).await;

    follower.pager.discard_dirty_main(REALM);
    drop(other_writer);
    follower.discard_failed_apply(&staged_image).await;
}

#[tokio::test(flavor = "current_thread")]
async fn failed_apply_cleanup_waits_for_the_writer_lock() {
    let fixture = follower_with_delta().await;
    let follower = &fixture.follower;
    let other_writer = follower.writer.lock().await;
    let page_id = write_dirty_page(follower, other_writer.next_page_id).await;

    let staged_image = staged_image_path(&follower.main_db_path);
    let cleanup = follower.discard_failed_apply(&staged_image);
    tokio::pin!(cleanup);
    tokio::select! {
        biased;
        () = &mut cleanup => panic!("the cleanup ran under another writer's lock"),
        () = tokio::task::yield_now() => {}
    }
    assert_dirty_page_resident(follower, page_id).await;

    drop(other_writer);
    cleanup.await;
    assert!(
        follower
            .pager
            .read_main_page(page_id, REALM, PageKind::Free)
            .await
            .is_err(),
        "with the lock released, the cleanup drops what remains and the read misses"
    );
}
