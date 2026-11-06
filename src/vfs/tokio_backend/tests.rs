use tokio::time::timeout;

use super::*;
use crate::vfs::gated::{LockStall, bounded, cancel_when};

fn tempdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    p.push(format!(
        "pagedb-tokio-unit-{}-{nanos}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&p).unwrap();
    p
}

#[test]
fn tempdir_helper_allocates_unique_roots() {
    let dirs: Vec<_> = (0..128).map(|_| tempdir()).collect();
    let mut paths = dirs.clone();
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), dirs.len());

    for dir in dirs {
        std::fs::remove_dir_all(dir).ok();
    }
}

#[test]
fn canonical_logical_paths_have_one_spelling() {
    assert_eq!(
        TokioVfs::canonical_logical_path("/main.db").unwrap(),
        "/main.db"
    );
    assert_eq!(
        TokioVfs::canonical_logical_path("main.db").unwrap(),
        "/main.db"
    );
    assert_eq!(
        TokioVfs::canonical_logical_path("/seg/file/").unwrap(),
        "/seg/file"
    );
    assert_eq!(
        TokioVfs::canonical_logical_path(r"seg\file").unwrap(),
        "/seg/file"
    );
    assert_eq!(TokioVfs::canonical_logical_path("/").unwrap(), "/");
}

#[test]
fn rejects_parent_current_and_empty_path_components() {
    let vfs = TokioVfs::new("/tmp/pagedb-root");

    for path in [
        "../escape",
        "/seg/../escape",
        "./main.db",
        "seg/./x",
        "seg//x",
    ] {
        let error = vfs.resolve(path).unwrap_err();
        match error {
            PagedbError::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn write_and_read_round_trip() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    let mut f = vfs.open("/hello", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"pagedb").await.unwrap();
    f.sync().await.unwrap();
    drop(f);

    let g = vfs.open("/hello", OpenMode::Read).await.unwrap();
    let mut buf = vec![0u8; 6];
    let n = g.read_at(0, &mut buf).await.unwrap();
    assert_eq!(n, 6);
    assert_eq!(&buf, b"pagedb");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_read_write() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    let mut f = vfs.open("/vec", OpenMode::CreateNew).await.unwrap();
    f.write_at_vectored(&[
        WriteReq {
            offset: 0,
            buf: b"foo",
        },
        WriteReq {
            offset: 10,
            buf: b"bar",
        },
    ])
    .await
    .unwrap();
    drop(f);

    let g = vfs.open("/vec", OpenMode::Read).await.unwrap();
    let mut a = [0u8; 3];
    let mut b = [0u8; 3];
    g.read_at_vectored(&mut [
        ReadReq {
            offset: 0,
            buf: &mut a,
        },
        ReadReq {
            offset: 10,
            buf: &mut b,
        },
    ])
    .await
    .unwrap();
    assert_eq!(&a, b"foo");
    assert_eq!(&b, b"bar");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn exclusive_lock_conflicts() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    let _h = vfs.lock_exclusive("/db").await.unwrap();
    assert!(vfs.lock_exclusive("/db").await.is_err());
    assert!(vfs.lock_shared("/db").await.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

/// Two independent `TokioVfs` instances over the same directory have
/// separate in-process lock tables, so only the OS-level lock can stop them
/// double-opening the same store. On Linux the OFD lock conflicts even
/// within one process; classic `F_SETLK` would not (it is process-owned and
/// self-non-conflicting). This is the defense-in-depth that keeps a single
/// buggy process from concurrently opening one store's writer twice.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn exclusive_lock_conflicts_across_vfs_instances_same_process() {
    let dir = tempdir();
    let vfs_a = TokioVfs::new(&dir);
    let vfs_b = TokioVfs::new(&dir);

    let _h = vfs_a.lock_exclusive("/db").await.unwrap();
    // Different instance, same process, same path: the in-proc guard cannot
    // see across instances, so the OFD lock must reject this.
    assert!(matches!(
        vfs_b.lock_exclusive("/db").await,
        Err(PagedbError::AlreadyLocked)
    ));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn shared_locks_coexist() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    let h1 = vfs.lock_shared("/db").await.unwrap();
    let h2 = vfs.lock_shared("/db").await.unwrap();
    assert!(vfs.lock_exclusive("/db").await.is_err());

    drop(h1);
    drop(h2);
    // After releasing both shared locks, exclusive should succeed.
    let h3 = vfs.lock_exclusive("/db").await.unwrap();
    drop(h3);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn list_dir_and_mkdir_all() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    vfs.mkdir_all("/sub/nested").await.unwrap();
    let mut f = vfs
        .open("/sub/nested/a", OpenMode::CreateNew)
        .await
        .unwrap();
    f.write_at(0, b"x").await.unwrap();
    drop(f);

    let entries = vfs.list_dir("/sub/nested").await.unwrap();
    assert!(entries.contains(&"a".to_string()));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn truncate_and_len() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    let mut f = vfs.open("/trunc", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"abcdefgh").await.unwrap();
    assert_eq!(f.len().await.unwrap(), 8);
    f.truncate(4).await.unwrap();
    assert_eq!(f.len().await.unwrap(), 4);

    std::fs::remove_dir_all(&dir).ok();
}

const DROPPED: &[u8] = b"dropped-write";
const NEXT: &[u8] = b"next-write-xx";
/// How long an operation runs while the dropped write is in flight. It cannot
/// finish in any time, so a slow machine cannot fail the test.
const PATIENCE: std::time::Duration = std::time::Duration::from_millis(100);

/// Leave one write in flight on `file`, parked until the returned stall drops.
/// The pool call waits for the cursor this holds, with no byte written yet.
async fn drop_a_write_in_flight(file: &mut TokioFile) -> LockStall {
    let cursor = Arc::clone(&file.cursor);
    let stall = LockStall::hold(move |park| {
        let _held = cursor.lock();
        park();
    });
    // The first poll spawns the pool call, and the yield then drops the future.
    cancel_when(file.write_at(0, DROPPED), tokio::task::yield_now()).await;
    stall
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_through_another_handle_lands_after_a_dropped_write() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);
    let mut dropped_on = vfs.open("/file", OpenMode::CreateNew).await.unwrap();
    let mut other = vfs.open("/file", OpenMode::ReadWrite).await.unwrap();
    let stall = drop_a_write_in_flight(&mut dropped_on).await;

    let mut next = Box::pin(other.write_at(0, NEXT));
    assert!(
        timeout(PATIENCE, &mut next).await.is_err(),
        "the next write overtook the dropped write"
    );
    drop(stall);
    bounded(next).await.unwrap();

    assert_eq!(std::fs::read(dir.join("file")).unwrap(), NEXT);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_on_the_same_handle_lands_after_a_dropped_write() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);
    let mut file = vfs.open("/file", OpenMode::CreateNew).await.unwrap();
    let stall = drop_a_write_in_flight(&mut file).await;

    let reqs = [WriteReq {
        offset: 0,
        buf: NEXT,
    }];
    let mut next = Box::pin(file.write_at_vectored(&reqs));
    assert!(
        timeout(PATIENCE, &mut next).await.is_err(),
        "the next write overtook the dropped write"
    );
    drop(stall);
    bounded(next).await.unwrap();

    assert_eq!(std::fs::read(dir.join("file")).unwrap(), NEXT);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn a_truncate_waits_for_a_dropped_write() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);
    let mut file = vfs.open("/file", OpenMode::CreateNew).await.unwrap();
    let stall = drop_a_write_in_flight(&mut file).await;

    let mut truncate = Box::pin(file.truncate(0));
    assert!(
        timeout(PATIENCE, &mut truncate).await.is_err(),
        "the truncate overtook the dropped write"
    );
    drop(stall);
    bounded(truncate).await.unwrap();

    assert_eq!(std::fs::read(dir.join("file")).unwrap(), b"");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn a_sync_waits_for_a_dropped_write() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);
    let mut file = vfs.open("/file", OpenMode::CreateNew).await.unwrap();
    let stall = drop_a_write_in_flight(&mut file).await;

    let mut sync = Box::pin(file.sync());
    assert!(
        timeout(PATIENCE, &mut sync).await.is_err(),
        "the sync overtook the dropped write"
    );
    drop(stall);
    bounded(sync).await.unwrap();

    assert_eq!(std::fs::read(dir.join("file")).unwrap(), DROPPED);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn an_open_waits_for_a_dropped_write_on_a_closed_handle() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);
    let mut file = vfs.open("/file", OpenMode::CreateNew).await.unwrap();
    let stall = drop_a_write_in_flight(&mut file).await;
    drop(file);

    let mut open = Box::pin(vfs.open("/file", OpenMode::Read));
    assert!(
        timeout(PATIENCE, &mut open).await.is_err(),
        "the open finished while the dropped write was in flight"
    );
    drop(stall);
    let reopened = bounded(open).await.unwrap();

    let mut buf = vec![0u8; DROPPED.len()];
    assert_eq!(reopened.read_at(0, &mut buf).await.unwrap(), DROPPED.len());
    assert_eq!(buf, DROPPED);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn read_only_rejects_writes() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    {
        let mut f = vfs.open("/ro", OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"data").await.unwrap();
    }

    let mut g = vfs.open("/ro", OpenMode::Read).await.unwrap();
    assert!(matches!(
        g.write_at(0, b"x").await,
        Err(PagedbError::ReadOnly)
    ));

    std::fs::remove_dir_all(&dir).ok();
}
