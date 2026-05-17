//! Cross-process lock test. On Unix, two TokioVfs instances pointing at the
//! same directory use fcntl(F_SETLK), so only one can hold an exclusive lock.
//! This verifies that two distinct VFS handles (simulating two processes with
//! the same in-memory state but independent fcntl states) cannot both acquire
//! the exclusive lock on the same path.

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn two_vfs_instances_exclusive_lock_conflict() {
    use pagedb::errors::PagedbError;
    use pagedb::vfs::tokio_backend::TokioVfs;
    use pagedb::vfs::Vfs;

    let dir = tempfile::tempdir().unwrap();
    let vfs1 = TokioVfs::new(dir.path());
    let vfs2 = TokioVfs::new(dir.path());

    // vfs1 acquires an exclusive lock.
    let _h1 = vfs1.lock_exclusive(".writer.lock").await.unwrap();

    // vfs2 must fail since vfs1 already holds fcntl F_WRLCK on the same file.
    let result = vfs2.lock_exclusive(".writer.lock").await;
    assert!(
        matches!(result, Err(PagedbError::AlreadyLocked)),
        "expected AlreadyLocked from second VFS instance, got: {result:?}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn two_vfs_instances_shared_and_exclusive_conflict() {
    use pagedb::errors::PagedbError;
    use pagedb::vfs::tokio_backend::TokioVfs;
    use pagedb::vfs::Vfs;

    let dir = tempfile::tempdir().unwrap();
    let vfs1 = TokioVfs::new(dir.path());
    let vfs2 = TokioVfs::new(dir.path());

    // vfs1 acquires a shared lock.
    let _h1 = vfs1.lock_shared(".frozen_readers.lock").await.unwrap();

    // vfs2 exclusive conflicts with vfs1 shared.
    let result = vfs2.lock_exclusive(".frozen_readers.lock").await;
    assert!(
        matches!(result, Err(PagedbError::AlreadyLocked)),
        "expected AlreadyLocked, got: {result:?}"
    );
}

#[cfg(not(unix))]
#[test]
fn cross_process_lock_not_applicable_on_non_unix() {
    // On non-Unix targets locking is in-process only; cross-process exclusion
    // is documented as best-effort. Nothing to assert here.
}
