use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, DbMode, OpenOptions, PagedbError, RealmId};

const PAGE: usize = 4096;

#[tokio::test(flavor = "current_thread")]
async fn open_standalone_succeeds_and_reports_mode() {
    let vfs = MemVfs::new();
    let db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(db.mode(), DbMode::Standalone);
    assert!(db.is_writer());
    assert!(!db.can_apply_incremental());
    assert!(!db.can_rekey_into_writer());
}

#[tokio::test(flavor = "current_thread")]
async fn second_standalone_open_returns_already_open() {
    let vfs = MemVfs::new();
    let _db = Db::open(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let err = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, PagedbError::AlreadyOpen));
}

#[tokio::test(flavor = "current_thread")]
async fn open_read_only_succeeds_when_no_writer() {
    let vfs = MemVfs::new();
    {
        // Create and close the database so the file exists.
        let _db = Db::open(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            OpenOptions::default(),
        )
        .await
        .unwrap();
    }
    let db = Db::open_read_only(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(db.mode(), DbMode::ReadOnly);
    assert!(!db.is_writer());
    assert!(db.can_rekey_into_writer());
}

#[tokio::test(flavor = "current_thread")]
async fn open_read_only_fails_when_writer_present() {
    let vfs = MemVfs::new();
    let _writer = Db::open(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let err = Db::open_read_only(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, PagedbError::WriterPresent));
}

#[tokio::test(flavor = "current_thread")]
async fn open_observer_succeeds_alongside_writer() {
    let vfs = MemVfs::new();
    let _writer = Db::open(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let obs = Db::open_observer(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(obs.mode(), DbMode::Observer);
}

#[tokio::test(flavor = "current_thread")]
async fn lock_released_on_drop_lets_second_open_succeed() {
    let vfs = MemVfs::new();
    {
        let _db = Db::open(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            OpenOptions::default(),
        )
        .await
        .unwrap();
    }
    let _db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn promote_to_follower_stub_returns_unsupported() {
    let vfs = MemVfs::new();
    let db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let err = db.promote_to_follower().await.err().unwrap();
    assert!(matches!(err, PagedbError::Unsupported));
}
