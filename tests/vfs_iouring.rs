//! Smoke tests for the io_uring VFS backend. Compiled on Linux only — on
//! other targets the backend module doesn't exist.
#![cfg(target_os = "linux")]

use pagedb::vfs::{IouringVfs, OpenMode, ReadReq, Vfs, VfsFile, WriteReq};

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    p.push(format!(
        "pagedb-iouring-{}-{}-{}",
        tag,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test(flavor = "current_thread")]
async fn write_and_read_exact() {
    let dir = tempdir("exact");
    let vfs = IouringVfs::new(&dir).unwrap();

    let payload = b"hello io_uring!";
    let mut f = vfs.open("/data", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, payload).await.unwrap();
    f.sync().await.unwrap();
    drop(f);

    let g = vfs.open("/data", OpenMode::Read).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    let n = g.read_at(0, &mut buf).await.unwrap();
    assert_eq!(n, payload.len());
    assert_eq!(&buf[..n], payload);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_write_and_read() {
    let dir = tempdir("vec");
    let vfs = IouringVfs::new(&dir).unwrap();

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
    f.sync().await.unwrap();
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
async fn vectored_write_rejects_invalid_offset_without_partial_write() {
    let dir = tempdir("vec_write_invalid_offset");
    let vfs = IouringVfs::new(&dir).unwrap();
    let mut file = vfs
        .open("/vec-write-invalid-offset", OpenMode::CreateNew)
        .await
        .unwrap();
    let writes = [
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
        .write_at_vectored(&writes)
        .await
        .expect_err("an invalid io_uring offset must reject the entire batch");
    assert!(matches!(error, pagedb::PagedbError::Io(_)));

    let mut actual = [0xff; 8];
    assert_eq!(file.read_at(0, &mut actual).await.unwrap(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_read_rejects_invalid_offset_without_touching_buffers() {
    let dir = tempdir("vec_read_invalid_offset");
    let vfs = IouringVfs::new(&dir).unwrap();
    let mut writer = vfs
        .open("/vec-read-invalid-offset", OpenMode::CreateNew)
        .await
        .unwrap();
    writer.write_at(0, b"visible!").await.unwrap();
    writer.sync().await.unwrap();
    drop(writer);

    let reader = vfs
        .open("/vec-read-invalid-offset", OpenMode::Read)
        .await
        .unwrap();
    let mut first = [0x55; 8];
    let mut second = [0x66; 1];
    let mut reads = [
        ReadReq {
            offset: 0,
            buf: &mut first,
        },
        ReadReq {
            offset: u64::MAX,
            buf: &mut second,
        },
    ];

    let error = reader
        .read_at_vectored(&mut reads)
        .await
        .expect_err("an invalid io_uring offset must reject before reading");
    assert!(matches!(error, pagedb::PagedbError::Io(_)));
    assert_eq!(first, [0x55; 8]);
    assert_eq!(second, [0x66; 1]);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_read_zero_fills_past_eof() {
    let dir = tempdir("vec_read_eof");
    let vfs = IouringVfs::new(&dir).unwrap();
    let mut writer = vfs
        .open("/vec-read-eof", OpenMode::CreateNew)
        .await
        .unwrap();
    writer.write_at(0, b"abc").await.unwrap();
    writer.sync().await.unwrap();
    drop(writer);

    let reader = vfs.open("/vec-read-eof", OpenMode::Read).await.unwrap();
    let mut actual = [0xff; 5];
    reader
        .read_at_vectored(&mut [ReadReq {
            offset: 0,
            buf: &mut actual,
        }])
        .await
        .unwrap();
    assert_eq!(actual, [b'a', b'b', b'c', 0, 0]);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn truncate_and_len() {
    let dir = tempdir("trunc");
    let vfs = IouringVfs::new(&dir).unwrap();

    let mut f = vfs.open("/trunc", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"abcdefgh").await.unwrap();
    assert_eq!(f.len().await.unwrap(), 8);
    f.truncate(4).await.unwrap();
    assert_eq!(f.len().await.unwrap(), 4);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_parent_directory_escape() {
    let dir = tempdir("root_escape");
    let root_name = dir.file_name().unwrap().to_string_lossy();
    let escaped_file = dir
        .parent()
        .unwrap()
        .join(format!("{root_name}-escaped-file"));
    let vfs = IouringVfs::new(&dir).unwrap();

    let open_result = vfs.open("../escaped-file", OpenMode::CreateNew).await;
    let escaped_file_was_created = escaped_file.exists();
    std::fs::remove_file(&escaped_file).ok();
    let error = match open_result {
        Ok(_) => panic!("open must reject paths outside the configured root"),
        Err(error) => error,
    };
    match error {
        pagedb::PagedbError::Io(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    assert!(!escaped_file_was_created);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn equivalent_lock_paths_share_one_domain() {
    let dir = tempdir("lock_alias");
    let vfs = IouringVfs::new(&dir).unwrap();
    let _held = vfs.lock_exclusive("/db.lock").await.unwrap();

    let error = match vfs.lock_exclusive("db.lock").await {
        Ok(_) => panic!("equivalent logical paths must share one lock domain"),
        Err(error) => error,
    };
    assert!(matches!(error, pagedb::PagedbError::AlreadyLocked));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn sync_dir_smoke() {
    let dir = tempdir("syncdir");
    let vfs = IouringVfs::new(&dir).unwrap();

    vfs.mkdir_all("/sub").await.unwrap();
    let mut f = vfs.open("/sub/x", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"x").await.unwrap();
    f.sync().await.unwrap();
    drop(f);
    // Rename and sync the directory.
    vfs.rename("/sub/x", "/sub/y").await.unwrap();
    vfs.sync_dir("/sub").await.unwrap();

    let entries = vfs.list_dir("/sub").await.unwrap();
    assert!(entries.contains(&"y".to_string()));
    assert!(!entries.contains(&"x".to_string()));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn exclusive_lock_conflicts() {
    let dir = tempdir("lock_excl");
    let vfs = IouringVfs::new(&dir).unwrap();

    let _h = vfs.lock_exclusive("/db.lock").await.unwrap();
    assert!(vfs.lock_exclusive("/db.lock").await.is_err());
    assert!(vfs.lock_shared("/db.lock").await.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn shared_locks_coexist() {
    let dir = tempdir("lock_shared");
    let vfs = IouringVfs::new(&dir).unwrap();

    let h1 = vfs.lock_shared("/db.lock").await.unwrap();
    let h2 = vfs.lock_shared("/db.lock").await.unwrap();
    assert!(vfs.lock_exclusive("/db.lock").await.is_err());
    drop(h1);
    drop(h2);
    let h3 = vfs.lock_exclusive("/db.lock").await.unwrap();
    drop(h3);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn read_only_rejects_writes() {
    let dir = tempdir("ro");
    let vfs = IouringVfs::new(&dir).unwrap();

    {
        let mut f = vfs.open("/ro", OpenMode::CreateNew).await.unwrap();
        f.write_at(0, b"data").await.unwrap();
    }

    let mut g = vfs.open("/ro", OpenMode::Read).await.unwrap();
    assert!(matches!(
        g.write_at(0, b"x").await,
        Err(pagedb::PagedbError::ReadOnly)
    ));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "current_thread")]
async fn supports_direct_io_is_true() {
    let dir = tempdir("dio");
    let vfs = IouringVfs::new(&dir).unwrap();

    let mut f = vfs.open("/x", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"x").await.unwrap();
    drop(f);

    let g = vfs.open("/x", OpenMode::Read).await.unwrap();
    assert!(g.supports_direct_io());

    std::fs::remove_dir_all(&dir).ok();
}
