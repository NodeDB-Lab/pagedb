use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::{OpenMode, Vfs, VfsFile};
use pagedb::{Db, DbMode, OpenOptions, PagedbError, RealmId, SegmentKind};

const PAGE: usize = 4096;
const SENTINEL_PATHS: [&str; 4] = [
    ".writer.lock",
    ".frozen_readers.lock",
    ".observers.lock",
    ".acquisition.lock",
];

async fn seed_sentinel_files(vfs: &MemVfs) {
    for path in SENTINEL_PATHS {
        let mut file = vfs.open(path, OpenMode::CreateNew).await.unwrap();
        file.write_at(0, path.as_bytes()).await.unwrap();
        file.sync().await.unwrap();
    }
}

async fn sentinel_contents(vfs: &MemVfs) -> Vec<Vec<u8>> {
    let mut contents = Vec::new();
    for path in SENTINEL_PATHS {
        let file = vfs.open(path, OpenMode::Read).await.unwrap();
        let mut bytes = vec![0; path.len()];
        file.read_at(0, &mut bytes).await.unwrap();
        contents.push(bytes);
    }
    contents
}

async fn staging_directory_snapshot(vfs: &MemVfs) -> (bool, Option<Vec<String>>) {
    match vfs.list_dir("seg/.staging").await {
        Ok(entries) => (true, Some(entries)),
        Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            (false, None)
        }
        Err(error) => panic!("reading staging directory failed: {error}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn missing_database_read_only_open_does_not_bootstrap_or_change_sentinels() {
    let vfs = MemVfs::new();
    seed_sentinel_files(&vfs).await;
    let sentinels_before = sentinel_contents(&vfs).await;

    let err = Db::open_read_only(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .err()
    .unwrap();

    assert!(matches!(err, PagedbError::NotFound));
    assert!(matches!(
        vfs.open("/main.db", OpenMode::Read).await,
        Err(PagedbError::Io(_))
    ));
    assert_eq!(sentinel_contents(&vfs).await, sentinels_before);
}

#[tokio::test(flavor = "current_thread")]
async fn missing_database_observer_open_does_not_bootstrap_or_change_sentinels() {
    let vfs = MemVfs::new();
    seed_sentinel_files(&vfs).await;
    let sentinels_before = sentinel_contents(&vfs).await;

    let err = Db::open_observer(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .err()
    .unwrap();

    assert!(matches!(err, PagedbError::NotFound));
    assert!(matches!(
        vfs.open("/main.db", OpenMode::Read).await,
        Err(PagedbError::Io(_))
    ));
    assert_eq!(sentinel_contents(&vfs).await, sentinels_before);
}

#[tokio::test(flavor = "current_thread")]
async fn missing_database_standalone_open_bootstraps() {
    let vfs = MemVfs::new();

    let db = Db::open(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(db.mode(), DbMode::Standalone);
    assert!(vfs.open("/main.db", OpenMode::Read).await.is_ok());
}

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
async fn fresh_databases_partition_nonce_space_with_random_identity_and_salt() {
    let first_vfs = MemVfs::new();
    let second_vfs = MemVfs::new();
    let _first = Db::open(
        first_vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let _second = Db::open(
        second_vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();

    let mut first_header = [0u8; 48];
    first_vfs
        .open("/main.db", OpenMode::Read)
        .await
        .unwrap()
        .read_at(0, &mut first_header)
        .await
        .unwrap();
    let mut second_header = [0u8; 48];
    second_vfs
        .open("/main.db", OpenMode::Read)
        .await
        .unwrap()
        .read_at(0, &mut second_header)
        .await
        .unwrap();

    assert_ne!(&first_header[16..32], &second_header[16..32]);
    assert_ne!(&first_header[32..48], &second_header[32..48]);
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
async fn read_only_handle_promotes_to_follower_through_the_supported_transition() {
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
    let read_only = Db::open_read_only(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();

    let follower = read_only.promote_to_follower().await.unwrap();

    assert_eq!(follower.mode(), DbMode::Follower);
    assert!(follower.can_apply_incremental());
    assert!(matches!(
        follower.begin_write().await,
        Err(PagedbError::ReadOnly)
    ));
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
async fn read_only_segment_creation_is_rejected_before_filesystem_mutation() {
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
    let db = Db::open_read_only(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();

    let (staging_exists_before, staging_entries_before) = staging_directory_snapshot(&vfs).await;
    let err = db
        .create_segment(RealmId::new([1; 16]), SegmentKind::Unspecified)
        .await
        .err()
        .unwrap();

    assert!(matches!(err, PagedbError::ReadOnly));
    let (staging_exists_after, staging_entries_after) = staging_directory_snapshot(&vfs).await;
    assert_eq!(staging_exists_after, staging_exists_before);
    assert_eq!(staging_entries_after, staging_entries_before);
}

#[tokio::test(flavor = "current_thread")]
async fn observer_segment_creation_is_rejected_before_filesystem_mutation() {
    let vfs = MemVfs::new();
    let db = Db::open(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    drop(db);
    let observer = Db::open_observer(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();

    let (staging_exists_before, staging_entries_before) = staging_directory_snapshot(&vfs).await;
    let err = observer
        .create_segment(RealmId::new([1; 16]), SegmentKind::Unspecified)
        .await
        .err()
        .unwrap();

    assert!(matches!(err, PagedbError::ReadOnly));
    let (staging_exists_after, staging_entries_after) = staging_directory_snapshot(&vfs).await;
    assert_eq!(staging_exists_after, staging_exists_before);
    assert_eq!(staging_entries_after, staging_entries_before);
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
