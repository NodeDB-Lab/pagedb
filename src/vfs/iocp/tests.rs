//! A write whose future was dropped keeps running on the blocking pool. These
//! tests hold its port lock, so it completes only after the release. The next
//! operation goes through a handle on another port, so only the order stops it.

use std::time::Duration;

use tokio::time::timeout;

use crate::vfs::gated::{LockStall, bounded, cancel_when};
use crate::vfs::iocp::{IocpFile, IocpVfs};
use crate::vfs::{OpenMode, Vfs, VfsFile};

const PATH: &str = "/file";
const DROPPED: &[u8] = b"dropped-write";
const NEXT: &[u8] = b"next-write-xx";
const PATIENCE: Duration = Duration::from_millis(100);

struct Fixture {
    dir: tempfile::TempDir,
    dropped_on: IocpFile,
    other: IocpFile,
    stall: LockStall,
}

async fn fixture_with_a_dropped_write() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut dropped_on = IocpVfs::new(dir.path())
        .unwrap()
        .open(PATH, OpenMode::CreateNew)
        .await
        .unwrap();
    let other = IocpVfs::new(dir.path())
        .unwrap()
        .open(PATH, OpenMode::ReadWrite)
        .await
        .unwrap();
    let port = dropped_on.port();
    let stall = LockStall::hold(move |park| {
        let _held = port.lock.lock();
        park();
    });
    cancel_when(dropped_on.write_at(0, DROPPED), tokio::task::yield_now()).await;
    Fixture {
        dir,
        dropped_on,
        other,
        stall,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_truncate_and_a_sync_wait_for_a_dropped_write() {
    let Fixture {
        dir,
        dropped_on,
        mut other,
        stall,
    } = fixture_with_a_dropped_write().await;

    assert!(
        timeout(PATIENCE, other.truncate(0)).await.is_err(),
        "the truncate overtook the dropped write"
    );
    assert!(
        timeout(PATIENCE, other.sync()).await.is_err(),
        "the sync overtook the dropped write"
    );
    drop(stall);
    bounded(other.sync()).await.unwrap();
    drop((other, dropped_on));

    assert_eq!(std::fs::read(dir.path().join("file")).unwrap(), DROPPED);
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_through_another_handle_lands_after_a_dropped_write() {
    let Fixture {
        dir,
        dropped_on,
        mut other,
        stall,
    } = fixture_with_a_dropped_write().await;

    let mut next = Box::pin(other.write_at(0, NEXT));
    assert!(
        timeout(PATIENCE, &mut next).await.is_err(),
        "the next write overtook the dropped write"
    );
    drop(stall);
    bounded(next).await.unwrap();
    bounded(other.sync()).await.unwrap();
    drop((other, dropped_on));

    assert_eq!(std::fs::read(dir.path().join("file")).unwrap(), NEXT);
}
