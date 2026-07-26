use pagedb::errors::PagedbError;
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::{OpenMode, ReadReq, Vfs, VfsFile, WriteReq};

#[tokio::test(flavor = "current_thread")]
async fn round_trip_read_write() {
    let vfs = MemVfs::new();
    let mut f = vfs.open("/x", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"hello").await.unwrap();
    f.write_at(5, b" world").await.unwrap();

    let g = vfs.open("/x", OpenMode::Read).await.unwrap();
    let mut buf = vec![0u8; 11];
    let n = g.read_at(0, &mut buf).await.unwrap();
    assert_eq!(n, 11);
    assert_eq!(&buf, b"hello world");
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_read_write_round_trip() {
    let vfs = MemVfs::new();
    let mut f = vfs.open("/x", OpenMode::CreateNew).await.unwrap();
    let w = vec![
        WriteReq {
            offset: 0,
            buf: b"AAAA",
        },
        WriteReq {
            offset: 100,
            buf: b"BBBB",
        },
    ];
    f.write_at_vectored(&w).await.unwrap();

    let mut a = [0u8; 4];
    let mut b = [0u8; 4];
    let mut reqs = [
        ReadReq {
            offset: 0,
            buf: &mut a,
        },
        ReadReq {
            offset: 100,
            buf: &mut b,
        },
    ];
    f.read_at_vectored(&mut reqs).await.unwrap();
    assert_eq!(&a, b"AAAA");
    assert_eq!(&b, b"BBBB");
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_write_rejects_offset_overflow_without_partial_write() {
    let vfs = MemVfs::new();
    let mut file = vfs.open("/x", OpenMode::CreateNew).await.unwrap();
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
}

#[tokio::test(flavor = "current_thread")]
async fn vectored_read_zero_fills_past_eof() {
    let vfs = MemVfs::new();
    let mut f = vfs.open("/x", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"abc").await.unwrap();
    let mut buf = [0xffu8; 8];
    let mut reqs = [ReadReq {
        offset: 0,
        buf: &mut buf,
    }];
    f.read_at_vectored(&mut reqs).await.unwrap();
    assert_eq!(&buf, b"abc\0\0\0\0\0");
}

#[tokio::test(flavor = "current_thread")]
async fn rename_while_open_keeps_handle_alive() {
    let vfs = MemVfs::new();
    let mut f = vfs.open("/from", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"first").await.unwrap();
    vfs.rename("/from", "/to").await.unwrap();
    // Open handle still works.
    f.write_at(5, b" second").await.unwrap();

    // The renamed path has both writes.
    let g = vfs.open("/to", OpenMode::Read).await.unwrap();
    let mut buf = vec![0u8; 12];
    let n = g.read_at(0, &mut buf).await.unwrap();
    assert_eq!(n, 12);
    assert_eq!(&buf, b"first second");

    // /from is gone.
    let err = vfs
        .open("/from", OpenMode::Read)
        .await
        .err()
        .expect("opened gone path");
    assert!(matches!(err, PagedbError::Io(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn exclusive_lock_blocks_second_exclusive_same_path() {
    let vfs = MemVfs::new();
    let _a = vfs.lock_exclusive("/p").await.unwrap();
    let err = vfs.lock_exclusive("/p").await.err().unwrap();
    assert!(matches!(err, PagedbError::AlreadyLocked));
}

#[tokio::test(flavor = "current_thread")]
async fn shared_lock_coexists_then_blocks_exclusive() {
    let vfs = MemVfs::new();
    let _a = vfs.lock_shared("/p").await.unwrap();
    let _b = vfs.lock_shared("/p").await.unwrap();
    let err = vfs.lock_exclusive("/p").await.err().unwrap();
    assert!(matches!(err, PagedbError::AlreadyLocked));
}

#[tokio::test(flavor = "current_thread")]
async fn exclusive_blocks_shared_same_path() {
    let vfs = MemVfs::new();
    let _a = vfs.lock_exclusive("/p").await.unwrap();
    let err = vfs.lock_shared("/p").await.err().unwrap();
    assert!(matches!(err, PagedbError::AlreadyLocked));
}

#[tokio::test(flavor = "current_thread")]
async fn different_paths_are_independent_lock_domains() {
    let vfs = MemVfs::new();
    let _a = vfs.lock_exclusive("/p1").await.unwrap();
    let _b = vfs.lock_exclusive("/p2").await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn lock_releases_on_drop() {
    let vfs = MemVfs::new();
    {
        let _a = vfs.lock_exclusive("/p").await.unwrap();
    }
    let _b = vfs.lock_exclusive("/p").await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn sync_dir_is_no_op() {
    let vfs = MemVfs::new();
    vfs.sync_dir("/any/where").await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn mkdir_all_is_idempotent() {
    let vfs = MemVfs::new();
    vfs.mkdir_all("/a/b/c").await.unwrap();
    vfs.mkdir_all("/a/b/c").await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn list_dir_returns_direct_children() {
    let vfs = MemVfs::new();
    vfs.open("/d/a", OpenMode::CreateNew).await.unwrap();
    vfs.open("/d/b", OpenMode::CreateNew).await.unwrap();
    vfs.open("/d/sub/deep", OpenMode::CreateNew).await.unwrap();
    let entries = vfs.list_dir("/d").await.unwrap();
    assert_eq!(entries, vec!["a".to_string(), "b".to_string()]);
}

#[tokio::test(flavor = "current_thread")]
async fn truncate_shrinks_and_zero_extends() {
    let vfs = MemVfs::new();
    let mut f = vfs.open("/x", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, &[0xab; 100]).await.unwrap();
    f.truncate(50).await.unwrap();
    assert_eq!(f.len().await.unwrap(), 50);
    f.truncate(150).await.unwrap();
    assert_eq!(f.len().await.unwrap(), 150);
    let mut buf = vec![0xff; 100];
    let n = f.read_at(50, &mut buf).await.unwrap();
    assert_eq!(n, 100);
    assert!(buf.iter().all(|b| *b == 0));
}

#[tokio::test(flavor = "current_thread")]
async fn create_new_fails_if_exists() {
    let vfs = MemVfs::new();
    vfs.open("/x", OpenMode::CreateNew).await.unwrap();
    let err = vfs.open("/x", OpenMode::CreateNew).await.err().unwrap();
    assert!(matches!(err, PagedbError::Io(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn read_mode_handle_cannot_write() {
    let vfs = MemVfs::new();
    vfs.open("/x", OpenMode::CreateNew).await.unwrap();
    let mut g = vfs.open("/x", OpenMode::Read).await.unwrap();
    let err = g.write_at(0, b"nope").await.err().unwrap();
    assert!(matches!(err, PagedbError::ReadOnly));
}

/// The in-memory backend is the one nearly every test runs on, so it has to
/// honour the same logical-path contract as the native backends. Spellings that
/// name one file must occupy one lock domain here too, or the suite stops being
/// able to catch path aliasing at all.
#[tokio::test(flavor = "current_thread")]
async fn equivalent_spellings_share_one_lock_domain() {
    let vfs = MemVfs::new();
    let held = vfs.lock_exclusive("/db.lock").await.unwrap();
    for alias in ["db.lock", "/db.lock", "db.lock/"] {
        assert!(
            matches!(
                vfs.lock_exclusive(alias).await,
                Err(pagedb::PagedbError::AlreadyLocked)
            ),
            "{alias:?} must contend with the held lock"
        );
    }
    drop(held);
    vfs.lock_exclusive("db.lock").await.unwrap();
}

/// Equivalent spellings must also name one file.
#[tokio::test(flavor = "current_thread")]
async fn equivalent_spellings_name_one_file() {
    let vfs = MemVfs::new();
    let mut f = vfs.open("seg/one", OpenMode::CreateNew).await.unwrap();
    f.write_at(0, b"payload").await.unwrap();
    drop(f);

    let mut buf = [0u8; 7];
    let g = vfs.open("/seg/one", OpenMode::Read).await.unwrap();
    assert_eq!(g.read_at(0, &mut buf).await.unwrap(), 7);
    assert_eq!(&buf, b"payload");
    assert_eq!(vfs.list_dir("/seg").await.unwrap(), vec!["one".to_string()]);
}

/// A path that escapes the root is rejected by the in-memory backend as well.
#[tokio::test(flavor = "current_thread")]
async fn a_path_that_escapes_the_root_is_rejected() {
    let vfs = MemVfs::new();
    for escape in ["../escaped", "a/../../escaped", "a/C:/b"] {
        assert!(
            vfs.open(escape, OpenMode::CreateNew).await.is_err(),
            "{escape:?} must not open"
        );
    }
}
