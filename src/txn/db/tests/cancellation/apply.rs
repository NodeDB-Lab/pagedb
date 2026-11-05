//! `apply_incremental` dropped before and after its rename.
//!
//! An apply needs a backend with a root path, so these tests gate `TokioVfs`.

use tempfile::TempDir;

use crate::catalog::codec::SegmentKind;
use crate::options::OpenOptions;
use crate::pager::core::FileKey;
use crate::segment::types::SegmentPageKind;
use crate::vfs::gated::{Gated, cancel_when};
use crate::vfs::tokio_backend::TokioVfs;
use crate::{CommitId, Db};

use super::support::{KEK, PAGE, REALM, poisoned_commit};

struct Fixture {
    vfs: Gated<TokioVfs>,
    follower: Db<Gated<TokioVfs>>,
    base: CommitId,
    target: CommitId,
    delta_dir: TempDir,
    _dirs: [TempDir; 3],
}

fn tempdir() -> TempDir {
    tempfile::tempdir().unwrap()
}

/// A follower at its base commit, and a delta that links a segment. The segment
/// gives the apply a journal, and the rewritten trees give it a reclaim set.
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

    let mut segment = source
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    segment
        .append_page(SegmentPageKind::Data, b"promoted")
        .await
        .unwrap();
    let meta = segment.seal().await.unwrap();
    let mut write = source.begin_write().await.unwrap();
    write.put(b"base", b"rewritten").await.unwrap();
    write.put(b"target", b"value").await.unwrap();
    write.link_segment("promoted", &meta).await.unwrap();
    let target = write.commit().await.unwrap();
    source
        .snapshot_incremental_to(base, delta_dir.path())
        .await
        .unwrap();
    drop(source);

    let restored =
        Db::<TokioVfs>::restore_from(snap_dir.path(), dst_dir.path(), OpenOptions::default(), KEK)
            .await
            .unwrap();
    drop(restored);
    let vfs = Gated::over(TokioVfs::new(dst_dir.path()));
    let follower = Db::open_read_only(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap()
        .promote_to_follower()
        .await
        .unwrap();
    Fixture {
        vfs,
        follower,
        base,
        target,
        delta_dir,
        _dirs: [src_dir, snap_dir, dst_dir],
    }
}

/// The rename has landed. The published snapshot names base roots over the target
/// image, and the journal has not run.
#[tokio::test(flavor = "current_thread")]
async fn apply_dropped_after_its_rename_poisons_and_reopens_at_the_target() {
    let fixture = follower_with_delta().await;
    let dir_sync = fixture.vfs.park_next_sync_dir("/");

    cancel_when(
        Box::pin(fixture.follower.apply_incremental(fixture.delta_dir.path())),
        dir_sync.wait_until_parked(),
    )
    .await;

    assert_eq!(
        poisoned_commit(fixture.follower.begin_read().await),
        fixture.target
    );
    assert_eq!(fixture.follower.latest_commit(), fixture.base);
    let Fixture {
        vfs,
        follower,
        target,
        _dirs,
        ..
    } = fixture;
    drop(follower);

    let reopened = Db::open_follower(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(reopened.latest_commit(), target);
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"target").await.unwrap().as_deref(),
        Some(b"value".as_slice())
    );
    let segment = reopened.open_segment(REALM, "promoted").await.unwrap();
    assert!(segment.read_page(1).await.unwrap().starts_with(b"promoted"));
}

/// The journal directory sync runs before the rename. The apply has already
/// staged its free list and history through the Pager. Those pages sit in the
/// cache under ids the live image also uses.
#[tokio::test(flavor = "current_thread")]
async fn apply_dropped_before_its_rename_leaves_no_staged_pages_and_can_rerun() {
    let fixture = follower_with_delta().await;
    let journal_sync = fixture.vfs.park_next_sync_dir("applyjournal");

    cancel_when(
        Box::pin(fixture.follower.apply_incremental(fixture.delta_dir.path())),
        journal_sync.wait_until_parked(),
    )
    .await;

    fixture.follower.ensure_usable().unwrap();
    assert_eq!(fixture.follower.latest_commit(), fixture.base);
    {
        let pool = fixture.follower.pager.inner.buffer_pool.lock();
        assert_eq!(pool.dirty_for_file(FileKey::Main), Vec::<u64>::new());
        assert_eq!(pool.len(), 0, "staged pages stayed resident");
    }
    {
        let reader = fixture.follower.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"base").await.unwrap().as_deref(),
            Some(b"value".as_slice())
        );
        assert!(reader.get(b"target").await.unwrap().is_none());
    }

    fixture
        .follower
        .apply_incremental(fixture.delta_dir.path())
        .await
        .unwrap();
    assert_eq!(fixture.follower.latest_commit(), fixture.target);
    let reader = fixture.follower.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"base").await.unwrap().as_deref(),
        Some(b"rewritten".as_slice())
    );
}
