use pagedb::vfs::memory::MemVfs;
use pagedb::{CipherId, Db, OpenOptions, PagedbError, RealmId};

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

async fn cross_realm_is_refused_under(cipher: CipherId) {
    // realm_a creates and writes, then a caller opens the same store with a
    // different RealmId. Every page realm_a wrote is AAD-bound to realm_a, so
    // realm_b could never read them — and the header records the realm, so the
    // open is refused before a single page is touched.
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
    let err = Db::open(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([2; 16]),
        OpenOptions::default(),
    )
    .await
    .err()
    .expect("opening under the wrong realm must be refused");
    assert!(
        matches!(
            err,
            PagedbError::RealmMismatch { stored, supplied }
                if stored == RealmId::new([1; 16]) && supplied == RealmId::new([2; 16])
        ),
        "a misrouted realm must name both realms rather than read as damage: {err:?}"
    );

    // The refusal must be non-destructive: the rightful realm still opens and
    // still sees its data.
    let db_a = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let r = db_a.begin_read().await.unwrap();
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn cross_realm_is_refused_aes_gcm() {
    cross_realm_is_refused_under(CipherId::Aes256Gcm).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cross_realm_is_refused_chacha() {
    cross_realm_is_refused_under(CipherId::ChaCha20Poly1305).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cross_realm_is_refused_plaintext_mac() {
    cross_realm_is_refused_under(CipherId::PlaintextMac).await;
}

/// The case that used to fail silently and permanently.
///
/// A store created under one realm and then reopened under a mistyped realm
/// while still *empty* had nothing to fail authentication on, so the writer
/// happily filled it with pages the original realm could never read. Binding
/// the realm at bootstrap is what turns that into a refusal.
#[tokio::test(flavor = "current_thread")]
async fn realm_typo_on_an_empty_store_is_refused_before_any_write() {
    let vfs = MemVfs::new();
    {
        let _created = Db::open(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            OpenOptions::default(),
        )
        .await
        .unwrap();
    }
    let err = Db::open(
        vfs.clone(),
        [9u8; 32],
        PAGE,
        RealmId::new([2; 16]),
        OpenOptions::default(),
    )
    .await
    .err()
    .expect("an empty store must still refuse a foreign realm");
    assert!(matches!(err, PagedbError::RealmMismatch { .. }), "{err:?}");

    // And the store is still usable by the realm that owns it.
    let db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let mut w = db.begin_write().await.unwrap();
    w.put(b"k", b"v").await.unwrap();
    w.commit().await.unwrap();
}
