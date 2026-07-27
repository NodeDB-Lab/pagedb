//! Mirrors `handle_modes.rs::second_standalone_open_returns_already_open` but
//! against the real disk-backed `TokioVfs` (the MemVfs version can't exercise
//! the `F_OFD_SETLK` fast-fail path). Also proves the rejected second open
//! left the first handle's data intact — the rejected path must be a no-op,
//! never a partial write.

use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{Db, OpenOptions, PagedbError, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [7u8; 32];
const REALM: RealmId = RealmId::new([3u8; 16]);

#[tokio::test(flavor = "current_thread")]
async fn second_disk_open_fails_fast_without_corrupting_first_handle() {
    let dir = tempfile::tempdir().unwrap();
    let vfs = TokioVfs::new(dir.path());

    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();

    // Write a key through the first (and only legitimate) handle.
    let mut w = db.begin_write().await.unwrap();
    w.put(b"key", b"value").await.unwrap();
    w.commit().await.unwrap();

    // A second `Db::open` on the same directory must fail fast — the
    // `.writer.lock` sentinel is already held — rather than racing the first
    // handle's writes.
    let err = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, PagedbError::AlreadyOpen));

    // The rejected open must not have touched the store: the first handle's
    // data is still readable through it.
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"key").await.unwrap().as_deref(),
        Some(b"value".as_slice())
    );
    drop(r);

    // Nor did it corrupt the durable state — a fresh read transaction on the
    // same live handle still sees the committed key.
    let mut w2 = db.begin_write().await.unwrap();
    w2.put(b"key2", b"value2").await.unwrap();
    w2.commit().await.unwrap();
    let r2 = db.begin_read().await.unwrap();
    assert_eq!(
        r2.get(b"key").await.unwrap().as_deref(),
        Some(b"value".as_slice())
    );
    assert_eq!(
        r2.get(b"key2").await.unwrap().as_deref(),
        Some(b"value2".as_slice())
    );
}
