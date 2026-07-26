//! Integration tests for the Windows `IocpVfs` backend.

#![cfg(target_os = "windows")]

use pagedb::vfs::{IocpVfs, OpenMode, ReadReq, Vfs, VfsFile, WriteReq};

fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("pagedb-vfs-iocp-")
        .tempdir()
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_round_trip_reopens_and_zero_fills_past_eof() {
    let dir = tempdir();
    let vfs = IocpVfs::new(dir.path()).unwrap();
    let mut writer = vfs.open("/round-trip", OpenMode::CreateNew).await.unwrap();
    writer
        .write_at_vectored(&[
            WriteReq {
                offset: 0,
                buf: b"abc",
            },
            WriteReq {
                offset: 8,
                buf: b"xyz",
            },
        ])
        .await
        .unwrap();
    writer.sync().await.unwrap();
    drop(writer);

    let reader = vfs.open("/round-trip", OpenMode::Read).await.unwrap();
    let mut first = [0xff; 3];
    let mut tail = [0xff; 5];
    reader
        .read_at_vectored(&mut [
            ReadReq {
                offset: 0,
                buf: &mut first,
            },
            ReadReq {
                offset: 8,
                buf: &mut tail,
            },
        ])
        .await
        .unwrap();

    assert_eq!(&first, b"abc");
    assert_eq!(tail, [b'x', b'y', b'z', 0, 0]);
}

#[tokio::test(flavor = "current_thread")]
async fn truncate_len_and_read_only_contract() {
    let dir = tempdir();
    let vfs = IocpVfs::new(dir.path()).unwrap();
    let mut writer = vfs.open("/truncate", OpenMode::CreateNew).await.unwrap();
    writer.write_at(0, b"abcdefgh").await.unwrap();
    assert_eq!(writer.len().await.unwrap(), 8);
    writer.truncate(4).await.unwrap();
    assert_eq!(writer.len().await.unwrap(), 4);
    drop(writer);

    let mut reader = vfs.open("/truncate", OpenMode::Read).await.unwrap();
    assert!(matches!(
        reader.write_at(0, b"x").await,
        Err(pagedb::errors::PagedbError::ReadOnly)
    ));
    assert!(matches!(
        reader.truncate(0).await,
        Err(pagedb::errors::PagedbError::ReadOnly)
    ));
    assert!(!reader.supports_direct_io());
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_parent_directory_escape() {
    let dir = tempdir();
    let root_name = dir.path().file_name().unwrap().to_string_lossy();
    let escaped_file = dir
        .path()
        .parent()
        .unwrap()
        .join(format!("{root_name}-escaped-file"));
    let vfs = IocpVfs::new(dir.path()).unwrap();

    let open_result = vfs.open("../escaped-file", OpenMode::CreateNew).await;
    let escaped_file_was_created = escaped_file.exists();
    std::fs::remove_file(&escaped_file).ok();
    let error = match open_result {
        Ok(_) => panic!("open must reject paths outside the configured root"),
        Err(error) => error,
    };
    match error {
        pagedb::errors::PagedbError::Io(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    assert!(!escaped_file_was_created);
}

#[tokio::test(flavor = "current_thread")]
async fn equivalent_lock_paths_share_one_domain() {
    let dir = tempdir();
    let vfs = IocpVfs::new(dir.path()).unwrap();
    let _held = vfs.lock_exclusive("/db.lock").await.unwrap();

    let error = match vfs.lock_exclusive("db.lock").await {
        Ok(_) => panic!("equivalent logical paths must share one lock domain"),
        Err(error) => error,
    };
    assert!(matches!(error, pagedb::errors::PagedbError::AlreadyLocked));
}
