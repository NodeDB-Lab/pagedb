use pagedb::vfs::memory::MemVfs;
use pagedb::{CipherId, CorruptionDetail, Db, OpenOptions, PagedbError, RealmId};

const PAGE: usize = 4096;

async fn round_trip_under_cipher(cipher: CipherId) {
    let vfs = MemVfs::new();
    let db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default().with_cipher(cipher),
    )
    .await
    .unwrap();
    let mut w = db.begin_write().await.unwrap();
    w.put(b"k", b"v").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_aes_gcm() {
    round_trip_under_cipher(CipherId::Aes256Gcm).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_chacha() {
    round_trip_under_cipher(CipherId::ChaCha20Poly1305).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_plaintext_mac() {
    round_trip_under_cipher(CipherId::PlaintextMac).await;
}

async fn cross_realm_fails_under(cipher: CipherId) {
    // realm_a writes, then realm_b opens the same VFS with a different RealmId.
    // The B+ tree root was AAD'd under realm_a; realm_b's read triggers tag failure.
    let vfs = MemVfs::new();
    {
        let db_a = Db::open(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            OpenOptions::default().with_cipher(cipher),
        )
        .await
        .unwrap();
        let mut w = db_a.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.commit().await.unwrap();
    }
    let db_b = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([2; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let r = db_b.begin_read().await.unwrap();
    let err = r.get(b"k").await.err().unwrap();
    assert!(
        matches!(
            err,
            PagedbError::Corruption(CorruptionDetail::PageUnverifiable { .. })
        ),
        "a misrouted realm must fail authentication and name the page: {err:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cross_realm_fails_aes_gcm() {
    cross_realm_fails_under(CipherId::Aes256Gcm).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cross_realm_fails_chacha() {
    cross_realm_fails_under(CipherId::ChaCha20Poly1305).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cross_realm_fails_plaintext_mac() {
    cross_realm_fails_under(CipherId::PlaintextMac).await;
}
