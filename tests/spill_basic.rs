//! Spill arena tests — round-trip, budget enforcement, and cleanup.
//!
//! Implementation note: each fresh `Db` starts `txn_seq` at 0; the first
//! `begin_write` call assigns `txn_seq = 1` via `fetch_add(0) + 1`, so the
//! spill tmp file for the first transaction is always `tmp/scratch-1`.

#![allow(clippy::drop_non_drop)]

use pagedb::errors::QuotaKind;
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::{OpenMode, Vfs};
use pagedb::{Db, OpenOptions, PagedbError, RealmId};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([1u8; 16]);

async fn open_with(vfs: MemVfs, scratch_bytes: usize) -> Db<MemVfs> {
    let opts = OpenOptions::default().with_scratch_bytes(scratch_bytes);
    Db::open_internal_with_options(vfs, [9u8; 32], PAGE, REALM, opts)
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn spill_round_trip() {
    let db = open_with(MemVfs::new(), 1024 * 1024).await;
    let mut w = db.begin_write().await.unwrap();
    let mut s = w.spill_scope();
    let h = s.append(b"hello").await.unwrap();
    let got = s.read(h).await.unwrap();
    assert_eq!(got, b"hello");
    drop(s);
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn spill_multiple_appends() {
    let db = open_with(MemVfs::new(), 1024 * 1024).await;
    let mut w = db.begin_write().await.unwrap();
    let mut s = w.spill_scope();
    let h0 = s.append(b"first").await.unwrap();
    let h1 = s.append(b"second").await.unwrap();
    let h2 = s.append(b"third chunk data").await.unwrap();
    assert_eq!(s.read(h0).await.unwrap(), b"first");
    assert_eq!(s.read(h1).await.unwrap(), b"second");
    assert_eq!(s.read(h2).await.unwrap(), b"third chunk data");
    drop(s);
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn spill_budget_enforced() {
    // Budget: 64 bytes. First append uses ~30 bytes plaintext + 16 tag = 46 bytes.
    // Second append of 50 plaintext + 16 tag = 66 bytes would push total to 112 > 64.
    let db = open_with(MemVfs::new(), 64).await;
    let mut w = db.begin_write().await.unwrap();
    let mut s = w.spill_scope();
    s.append(&[0u8; 30]).await.unwrap();
    let err = s.append(&[0u8; 50]).await.unwrap_err();
    assert!(
        matches!(
            err,
            PagedbError::Quota {
                kind: QuotaKind::ScratchPages,
                ..
            }
        ),
        "expected ScratchPages quota error, got: {err:?}"
    );
    drop(s);
    w.abort().await;
}

#[tokio::test(flavor = "current_thread")]
async fn spill_cleanup_on_commit() {
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_scratch_bytes(1024 * 1024);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts)
        .await
        .unwrap();
    {
        let mut w = db.begin_write().await.unwrap();
        let mut s = w.spill_scope();
        s.append(b"x").await.unwrap();
        drop(s);
        w.commit().await.unwrap();
    }
    // The tmp file should have been removed. The first txn always gets txn_seq=1.
    let res = vfs.open("tmp/scratch-1", OpenMode::Read).await;
    assert!(res.is_err(), "tmp file should be cleaned up after commit");
}

#[tokio::test(flavor = "current_thread")]
async fn spill_cleanup_on_abort() {
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_scratch_bytes(1024 * 1024);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts)
        .await
        .unwrap();
    {
        let mut w = db.begin_write().await.unwrap();
        let mut s = w.spill_scope();
        s.append(b"x").await.unwrap();
        drop(s);
        w.abort().await;
    }
    let res = vfs.open("tmp/scratch-1", OpenMode::Read).await;
    assert!(res.is_err(), "tmp file should be cleaned up after abort");
}

#[tokio::test(flavor = "current_thread")]
async fn spill_aead_protects_payload() {
    // Confirm bytes on disk are NOT plaintext.
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_scratch_bytes(1024 * 1024);
    let db = Db::open_internal_with_options(vfs.clone(), [9u8; 32], PAGE, REALM, opts)
        .await
        .unwrap();
    let mut w = db.begin_write().await.unwrap();
    let mut s = w.spill_scope();
    let _h = s.append(b"plaintext-payload").await.unwrap();

    // While the txn is alive, read raw bytes via the VFS.
    use pagedb::vfs::VfsFile;
    let f = vfs.open("tmp/scratch-1", OpenMode::Read).await.unwrap();
    let mut buf = vec![0u8; 128];
    let n = f.read_at(0, &mut buf).await.unwrap();
    let raw = &buf[..n];
    assert!(
        !raw.windows(b"plaintext-payload".len())
            .any(|w| w == b"plaintext-payload"),
        "plaintext must not appear verbatim in the spill file"
    );

    drop(s);
    w.abort().await;
}
