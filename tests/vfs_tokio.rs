#![cfg(not(target_arch = "wasm32"))]

//! Integration tests for `TokioVfs` — real disk I/O under a temporary directory.

use pagedb::errors::PagedbError;
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::vfs::{OpenMode, ReadReq, Vfs, VfsFile, WriteReq};

fn tempdir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    p.push(format!(
        "pagedb-vfs-tokio-{}-{nanos}-{sequence}",
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
async fn vectored_write_rejects_offset_overflow_without_partial_write() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);
    let mut file = vfs
        .open("/vec-overflow", OpenMode::CreateNew)
        .await
        .unwrap();
    let requests = [
        WriteReq {
            offset: 0,
            buf: b"kept-out",
        },
        WriteReq {
            offset: u64::MAX,
            buf: b"x",
        },
    ];

    let error = file
        .write_at_vectored(&requests)
        .await
        .expect_err("the invalid request must reject the entire vector");
    assert!(matches!(error, PagedbError::Io(_)));

    let mut actual = [0xff; 8];
    assert_eq!(file.read_at(0, &mut actual).await.unwrap(), 0);
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
async fn rejects_parent_directory_escape() {
    let dir = tempdir();
    let root_name = dir.file_name().unwrap().to_string_lossy();
    let escaped_file = dir
        .parent()
        .unwrap()
        .join(format!("{root_name}-escaped-file"));
    let escaped_dir = dir
        .parent()
        .unwrap()
        .join(format!("{root_name}-escaped-dir"));
    let vfs = TokioVfs::new(&dir);

    let open_result = vfs.open("../escaped-file", OpenMode::CreateNew).await;
    let escaped_file_was_created = escaped_file.exists();
    std::fs::remove_file(&escaped_file).ok();
    let open_error = match open_result {
        Ok(_) => panic!("open must reject paths outside the configured root"),
        Err(error) => error,
    };
    match open_error {
        PagedbError::Io(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    assert!(
        !escaped_file_was_created,
        "an invalid open path must not create a file outside the VFS root"
    );

    let mkdir_result = vfs.mkdir_all("../escaped-dir").await;
    let escaped_dir_was_created = escaped_dir.exists();
    std::fs::remove_dir_all(&escaped_dir).ok();
    let mkdir_error = mkdir_result.expect_err("mkdir_all must reject a root escape");
    match mkdir_error {
        PagedbError::Io(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    assert!(
        !escaped_dir_was_created,
        "an invalid mkdir path must not create a directory outside the VFS root"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn lock_paths_are_normalized_before_conflict_check() {
    let dir = tempdir();
    let vfs = TokioVfs::new(&dir);
    let _held = vfs.lock_exclusive("/db.lock").await.unwrap();

    let error = match vfs.lock_exclusive("db.lock").await {
        Ok(_) => panic!("equivalent logical paths must share one lock domain"),
        Err(error) => error,
    };
    assert!(matches!(error, PagedbError::AlreadyLocked));

    let error = match vfs.lock_shared("db.lock").await {
        Ok(_) => panic!("equivalent logical paths must share one lock domain"),
        Err(error) => error,
    };
    assert!(matches!(error, PagedbError::AlreadyLocked));
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
