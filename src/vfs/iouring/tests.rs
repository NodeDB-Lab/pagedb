//! A write whose future was dropped keeps running on the blocking pool. These
//! tests stall its ring, so it completes only after the release, and check what
//! the next operation on the same file does in that window.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::vfs::gated::{LockStall, bounded, cancel_when};
use crate::vfs::iouring::ring::{Ring, SharedRing};
use crate::vfs::iouring::{IouringFile, IouringVfs};
use crate::vfs::write_order::WriteOrder;
use crate::vfs::{OpenMode, Vfs, VfsFile};

const PATH: &str = "/file";
const DROPPED: &[u8] = b"dropped-write";
const NEXT: &[u8] = b"next-write-xx";

/// How long an operation runs while the dropped write is in flight. It cannot
/// finish in any time, so a slow machine cannot fail the test.
const PATIENCE: Duration = Duration::from_millis(100);

struct Fixture {
    dir: tempfile::TempDir,
    vfs: IouringVfs,
    file: IouringFile,
    free_ring: Arc<SharedRing>,
}

impl Fixture {
    fn contents(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("file")).unwrap()
    }
}

/// `None` where the kernel grants no ring. No `io_uring` backend exists there.
async fn fixture() -> Option<Fixture> {
    let dir = tempfile::tempdir().unwrap();
    let vfs = IouringVfs::new(dir.path()).ok()?;
    let file = vfs.open(PATH, OpenMode::CreateNew).await.unwrap();
    let free_ring = Ring::new().ok()?.inner;
    Some(Fixture {
        dir,
        vfs,
        file,
        free_ring,
    })
}

/// Leave one write in flight on `file`, parked until the returned stall drops.
/// Later operations on `file` use `free_ring`, so only the order stops them.
async fn drop_a_write_in_flight(file: &mut IouringFile, free_ring: &Arc<SharedRing>) -> LockStall {
    let stalled_ring = Ring::new().unwrap().inner;
    let stall = stalled_ring.stall();
    file.use_ring(stalled_ring);
    // The first poll spawns the pool call, and the yield then drops the future.
    cancel_when(file.write_at(0, DROPPED), tokio::task::yield_now()).await;
    file.use_ring(Arc::clone(free_ring));
    stall
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_waits_for_a_dropped_write_and_lands_after_it() {
    let Some(mut fixture) = fixture().await else {
        return;
    };
    let stall = drop_a_write_in_flight(&mut fixture.file, &fixture.free_ring).await;

    let mut next = Box::pin(fixture.file.write_at(0, NEXT));
    assert!(
        timeout(PATIENCE, &mut next).await.is_err(),
        "the next write finished while the dropped write was in flight"
    );
    drop(stall);
    bounded(next).await.unwrap();

    assert_eq!(fixture.contents(), NEXT);
}

#[tokio::test(flavor = "current_thread")]
async fn a_vectored_write_waits_for_a_dropped_write_and_lands_after_it() {
    let Some(mut fixture) = fixture().await else {
        return;
    };
    let stall = drop_a_write_in_flight(&mut fixture.file, &fixture.free_ring).await;

    let reqs = [crate::vfs::WriteReq {
        offset: 0,
        buf: NEXT,
    }];
    let mut next = Box::pin(fixture.file.write_at_vectored(&reqs));
    assert!(
        timeout(PATIENCE, &mut next).await.is_err(),
        "the next write finished while the dropped write was in flight"
    );
    drop(stall);
    bounded(next).await.unwrap();

    assert_eq!(fixture.contents(), NEXT);
}

/// `commit_header` writes through its own handle, so the order has to reach
/// across handles of one file.
#[tokio::test(flavor = "current_thread")]
async fn a_write_through_another_handle_waits_for_a_dropped_write() {
    let Some(mut fixture) = fixture().await else {
        return;
    };
    let stall = drop_a_write_in_flight(&mut fixture.file, &fixture.free_ring).await;

    let second_fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.dir.path().join("file"))
        .unwrap();
    let order = WriteOrder::for_file(&second_fd).unwrap();
    let mut other = IouringFile::new(second_fd, true, Arc::clone(&fixture.free_ring), order);
    let mut next = Box::pin(other.write_at(0, NEXT));
    assert!(
        timeout(PATIENCE, &mut next).await.is_err(),
        "a write through another handle overtook the dropped write"
    );
    drop(stall);
    bounded(next).await.unwrap();

    assert_eq!(fixture.contents(), NEXT);
}

/// A truncate that overtakes the write leaves the file regrown.
#[tokio::test(flavor = "current_thread")]
async fn a_truncate_waits_for_a_dropped_write() {
    let Some(mut fixture) = fixture().await else {
        return;
    };
    let stall = drop_a_write_in_flight(&mut fixture.file, &fixture.free_ring).await;

    let mut truncate = Box::pin(fixture.file.truncate(0));
    assert!(
        timeout(PATIENCE, &mut truncate).await.is_err(),
        "the truncate finished while the dropped write was in flight"
    );
    drop(stall);
    bounded(truncate).await.unwrap();

    assert_eq!(fixture.contents(), b"");
}

/// A sync that overtakes the write reports success for bytes it did not cover.
#[tokio::test(flavor = "current_thread")]
async fn a_sync_waits_for_a_dropped_write() {
    let Some(mut fixture) = fixture().await else {
        return;
    };
    let stall = drop_a_write_in_flight(&mut fixture.file, &fixture.free_ring).await;

    let mut sync = Box::pin(fixture.file.sync());
    assert!(
        timeout(PATIENCE, &mut sync).await.is_err(),
        "the sync finished while the dropped write was in flight"
    );
    drop(stall);
    bounded(sync).await.unwrap();

    assert_eq!(fixture.contents(), DROPPED);
}

/// A reopen after a poisoned handle reads the header slots. They must not change
/// under it, and the same goes for a handle closed with its write in flight.
#[tokio::test(flavor = "current_thread")]
async fn an_open_waits_for_a_dropped_write_on_a_closed_handle() {
    let Some(mut fixture) = fixture().await else {
        return;
    };
    let stall = drop_a_write_in_flight(&mut fixture.file, &fixture.free_ring).await;
    let Fixture { dir, vfs, file, .. } = fixture;
    drop(file);

    let mut open = Box::pin(vfs.open(PATH, OpenMode::Read));
    assert!(
        timeout(PATIENCE, &mut open).await.is_err(),
        "the open finished while the dropped write was in flight"
    );
    drop(stall);
    let reopened = bounded(open).await.unwrap();

    let mut buf = vec![0u8; DROPPED.len()];
    assert_eq!(
        reopened.read_at(0, &mut buf).await.unwrap(),
        DROPPED.len(),
        "the settled file holds the dropped write"
    );
    assert_eq!(buf, DROPPED);
    drop(dir);
}
