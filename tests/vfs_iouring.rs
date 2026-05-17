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
        Err(pagedb::errors::PagedbError::ReadOnly)
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
