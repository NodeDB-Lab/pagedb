//! `open_default` is what embedders that don't pick a backend actually get, so
//! it has to produce a VFS a real store can run on — on whichever backend the
//! kernel allowed. On Linux that is now a run-time choice: `io_uring` when a
//! ring is available, the thread pool when it is not.
//!
//! Forcing the ring to be refused is not portable (it needs a lowered
//! `RLIMIT_MEMLOCK`, a seccomp profile, or an old kernel), so the *trigger* is
//! not exercised here. What is exercised is that whichever arm is taken drives
//! a full open/commit/read cycle — the fallback arm's delegation is unit-tested
//! directly in `src/vfs/native.rs`.

use pagedb::vfs::open_default;
use pagedb::{Db, OpenOptions, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [9u8; 32];
const REALM: RealmId = RealmId::new([5u8; 16]);

#[tokio::test(flavor = "current_thread")]
async fn the_default_backend_runs_a_full_store_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let vfs = open_default(dir.path()).unwrap();

    let db = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();

    let mut write = db.begin_write().await.unwrap();
    write.put(b"key", b"value").await.unwrap();
    write.commit().await.unwrap();

    let read = db.begin_read().await.unwrap();
    assert_eq!(
        read.get(b"key").await.unwrap().as_deref(),
        Some(b"value".as_slice())
    );
}
