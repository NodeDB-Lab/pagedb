//! Cross-process sentinel-lock coverage for the native Tokio VFS.

#[cfg(unix)]
const HELPER_TEST: &str = "durability_tests::cross_process_lock::lock_holder_helper";

#[cfg(unix)]
fn wait_for_file(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "lock helper timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn lock_holder_helper() {
    use pagedb::vfs::Vfs;
    use pagedb::vfs::tokio_backend::TokioVfs;

    let Ok(root) = std::env::var("PAGEDB_LOCK_HELPER_ROOT") else {
        return;
    };
    let lock_path = std::env::var("PAGEDB_LOCK_HELPER_PATH").unwrap();
    let lock_kind = std::env::var("PAGEDB_LOCK_HELPER_KIND").unwrap();
    let ready = std::path::PathBuf::from(std::env::var("PAGEDB_LOCK_HELPER_READY").unwrap());
    let release = std::path::PathBuf::from(std::env::var("PAGEDB_LOCK_HELPER_RELEASE").unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let vfs = TokioVfs::new(root);

    if lock_kind == "exclusive" {
        let _lock = runtime.block_on(vfs.lock_exclusive(&lock_path)).unwrap();
        std::fs::write(&ready, b"ready").unwrap();
        wait_for_file(&release);
    } else {
        let _lock = runtime.block_on(vfs.lock_shared(&lock_path)).unwrap();
        std::fs::write(&ready, b"ready").unwrap();
        wait_for_file(&release);
    }
}

#[cfg(unix)]
async fn assert_conflict(lock_path: &str, holder_kind: &str) {
    use pagedb::errors::PagedbError;
    use pagedb::vfs::Vfs;
    use pagedb::vfs::tokio_backend::TokioVfs;

    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("holder.ready");
    let release = dir.path().join("holder.release");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(HELPER_TEST)
        .arg("--nocapture")
        .env("PAGEDB_LOCK_HELPER_ROOT", dir.path())
        .env("PAGEDB_LOCK_HELPER_PATH", lock_path)
        .env("PAGEDB_LOCK_HELPER_KIND", holder_kind)
        .env("PAGEDB_LOCK_HELPER_READY", &ready)
        .env("PAGEDB_LOCK_HELPER_RELEASE", &release)
        .spawn()
        .unwrap();
    wait_for_file(&ready);

    let vfs = TokioVfs::new(dir.path());
    let result = vfs.lock_exclusive(lock_path).await;

    std::fs::write(&release, b"release").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(matches!(result, Err(PagedbError::AlreadyLocked)));
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn exclusive_lock_conflicts_across_processes() {
    assert_conflict(".writer.lock", "exclusive").await;
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn shared_lock_conflicts_with_cross_process_exclusive_request() {
    assert_conflict(".frozen_readers.lock", "shared").await;
}

#[cfg(not(unix))]
#[test]
fn cross_process_lock_not_applicable_on_non_unix() {
    // Cross-process locking coverage is provided by each platform backend.
}
