//! Integration tests for `TokioVfs` — real disk I/O under a temporary directory.

use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::vfs::{OpenMode, ReadReq, Vfs, VfsFile, WriteReq};

fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("pagedb-vfs-tokio-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_file() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    {
        let mut f = vfs.open("/data", OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"hello").await.unwrap();
        f.sync().await.unwrap();
    }

    let g = vfs.open("/data", OpenMode::Read).await.unwrap();
    let mut buf = vec![0u8; 5];
    let n = g.read_at(0, &mut buf).await.unwrap();
    assert_eq!(n, 5);
    assert_eq!(&buf, b"hello");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_write_then_read() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    {
        let mut f = vfs.open("/vec", OpenMode::CreateNew).await.unwrap();
        f.write_at_vectored(&[
            WriteReq {
                offset: 0,
                buf: b"abc",
            },
            WriteReq {
                offset: 10,
                buf: b"xyz",
            },
        ])
        .await
        .unwrap();
        f.sync().await.unwrap();
    }

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
    assert_eq!(&a, b"abc");
    assert_eq!(&b, b"xyz");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn sync_dir_succeeds() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);
    vfs.mkdir_all("/sub").await.unwrap();
    // sync_dir is best-effort; must not error on supported platforms.
    vfs.sync_dir("/sub").await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn list_dir_returns_sorted_entries() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    for name in &["/files/c", "/files/a", "/files/b"] {
        let mut f = vfs.open(name, OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"x").await.unwrap();
    }

    let entries = vfs.list_dir("/files").await.unwrap();
    assert_eq!(entries, vec!["a", "b", "c"]);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn remove_is_idempotent() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    // Remove a non-existent path must not error.
    vfs.remove("/ghost").await.unwrap();

    {
        let mut f = vfs.open("/ghost", OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"data").await.unwrap();
    }
    vfs.remove("/ghost").await.unwrap();
    // Second remove of now-absent path must also succeed.
    vfs.remove("/ghost").await.unwrap();

    std::fs::remove_dir_all(&dir).ok();
}

/// Rename while an open handle exists. On POSIX, the handle remains bound to
/// the underlying inode data — subsequent writes through the old handle are
/// visible at the new path after the handle is dropped.
///
/// This test is `#[cfg(unix)]` because Windows does not permit renaming a file
/// while any process holds an open handle to it without `FILE_SHARE_DELETE`
/// (which `tokio::fs::OpenOptions` does not set). Cross-process rename semantics
/// on Windows are handled by the dedicated vfs-iocp backend.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn rename_while_open() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);

    let mut f = vfs.open("/from", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"first").await.unwrap();
    f.sync().await.unwrap();

    vfs.rename("/from", "/to").await.unwrap();

    // POSIX: the open handle keeps the inode alive; writes through it land at
    // the new path once the handle is closed.
    f.write_at(5, b" second").await.unwrap();
    f.sync().await.unwrap();
    drop(f);

    let g = vfs.open("/to", OpenMode::Read).await.unwrap();
    let mut buf = vec![0u8; 12];
    let n = g.read_at(0, &mut buf).await.unwrap();
    assert!(n >= 12, "expected >=12 bytes, got {n}");
    assert_eq!(&buf[..12], b"first second");

    std::fs::remove_dir_all(&dir).ok();
}
