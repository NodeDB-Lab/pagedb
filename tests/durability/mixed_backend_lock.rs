//! Cross-process exclusion between the two Linux backends.
//!
//! `open_default` degrades to the thread-pool backend when the kernel refuses
//! an `io_uring` ring, so two processes opening the same store can legitimately
//! end up on different backends. The store's single-writer guarantee rests
//! entirely on the `.writer.lock` sentinel, which means an `io_uring`-backed
//! process and a thread-pool-backed process must still exclude each other. If
//! they did not, the fallback would let two writers into one store.
//!
//! Both directions are covered: neither backend may be the one that wins.

#[cfg(target_os = "linux")]
const HELPER_TEST: &str = "durability_tests::mixed_backend_lock::mixed_lock_holder_helper";

#[cfg(target_os = "linux")]
const LOCK_PATH: &str = ".writer.lock";

/// Wait for the helper to report its state and return what it reported:
/// `ready` when it holds the lock, `skip` when it could not use its backend.
#[cfg(target_os = "linux")]
fn wait_for_report(path: &std::path::Path) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(report) = std::fs::read_to_string(path) {
            if !report.is_empty() {
                return report;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "mixed-backend lock helper timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn wait_for_file(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "mixed-backend lock helper timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Child process: take the writer sentinel on the requested backend and hold it
/// until told to let go.
#[cfg(target_os = "linux")]
#[test]
fn mixed_lock_holder_helper() {
    use pagedb::vfs::Vfs;
    use pagedb::vfs::{IouringVfs, tokio_backend::TokioVfs};

    let Ok(root) = std::env::var("PAGEDB_MIXED_LOCK_ROOT") else {
        return;
    };
    let backend = std::env::var("PAGEDB_MIXED_LOCK_BACKEND").unwrap();
    let ready = std::path::PathBuf::from(std::env::var("PAGEDB_MIXED_LOCK_READY").unwrap());
    let release = std::path::PathBuf::from(std::env::var("PAGEDB_MIXED_LOCK_RELEASE").unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    if backend == "iouring" {
        let Ok(vfs) = IouringVfs::new(&root) else {
            // No ring here: report it so the parent skips rather than reading
            // the missing lock as a locking failure.
            std::fs::write(&ready, b"skip").unwrap();
            return;
        };
        let _lock = runtime.block_on(vfs.lock_exclusive(LOCK_PATH)).unwrap();
        std::fs::write(&ready, b"ready").unwrap();
        wait_for_file(&release);
    } else {
        let vfs = TokioVfs::new(&root);
        let _lock = runtime.block_on(vfs.lock_exclusive(LOCK_PATH)).unwrap();
        std::fs::write(&ready, b"ready").unwrap();
        wait_for_file(&release);
    }
}

/// Hold the sentinel in a child process on `holder_backend`, then assert this
/// process cannot take it on the other backend.
#[cfg(target_os = "linux")]
async fn assert_backends_exclude(holder_backend: &str) {
    use pagedb::PagedbError;
    use pagedb::vfs::Vfs;
    use pagedb::vfs::{IouringVfs, tokio_backend::TokioVfs};

    let dir = tempfile::tempdir().unwrap();

    // The requester's backend is whichever one the holder is not.
    let requester_iouring = if holder_backend == "iouring" {
        None
    } else {
        match IouringVfs::new(dir.path()) {
            Ok(vfs) => Some(vfs),
            // This machine cannot hand out a ring at all, so the mixed-backend
            // situation this test describes cannot arise on it.
            Err(_) => return,
        }
    };

    let ready = dir.path().join("holder.ready");
    let release = dir.path().join("holder.release");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(HELPER_TEST)
        .arg("--nocapture")
        .env("PAGEDB_MIXED_LOCK_ROOT", dir.path())
        .env("PAGEDB_MIXED_LOCK_BACKEND", holder_backend)
        .env("PAGEDB_MIXED_LOCK_READY", &ready)
        .env("PAGEDB_MIXED_LOCK_RELEASE", &release)
        .spawn()
        .unwrap();

    if wait_for_report(&ready) == "skip" {
        assert!(child.wait().unwrap().success());
        return;
    }

    let result = match &requester_iouring {
        Some(vfs) => vfs.lock_exclusive(LOCK_PATH).await.map(|_| ()),
        None => TokioVfs::new(dir.path())
            .lock_exclusive(LOCK_PATH)
            .await
            .map(|_| ()),
    };

    std::fs::write(&release, b"release").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(
        matches!(result, Err(PagedbError::AlreadyLocked)),
        "a {holder_backend}-backed process holds the writer sentinel, so the \
         other backend must be refused; got {result:?}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn a_thread_pool_process_cannot_take_a_lock_an_iouring_process_holds() {
    assert_backends_exclude("iouring").await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn an_iouring_process_cannot_take_a_lock_a_thread_pool_process_holds() {
    assert_backends_exclude("tokio").await;
}

#[cfg(not(target_os = "linux"))]
#[test]
fn mixed_backend_locking_not_applicable_off_linux() {
    // The io_uring backend, and therefore the mixed-backend case, is Linux-only.
}
