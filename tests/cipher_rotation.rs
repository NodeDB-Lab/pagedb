/// Verify that pages written under one cipher can be read back correctly, and
/// that each cipher variant works independently. The per-page epoch+cipher
/// dispatch reads the `cipher_id` from the on-disk header byte rather than
/// from the pager's current configuration, so old pages remain readable after
/// the configured cipher changes.
use pagedb::vfs::memory::MemVfs;
use pagedb::{CipherId, Db, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [5u8; 32];
const REALM: RealmId = RealmId::new([2u8; 16]);

#[tokio::test(flavor = "current_thread")]
async fn aes256gcm_write_read_round_trip() {
    let db = Db::open_internal_with_cipher(MemVfs::new(), KEK, PAGE, REALM, CipherId::Aes256Gcm)
        .await
        .unwrap();
    let mut w = db.begin_write().await.unwrap();
    w.put(b"aes_key", b"aes_val").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"aes_key").await.unwrap().as_deref(),
        Some(b"aes_val".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn chacha20poly1305_write_read_round_trip() {
    let db =
        Db::open_internal_with_cipher(MemVfs::new(), KEK, PAGE, REALM, CipherId::ChaCha20Poly1305)
            .await
            .unwrap();
    let mut w = db.begin_write().await.unwrap();
    w.put(b"cc_key", b"cc_val").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"cc_key").await.unwrap().as_deref(),
        Some(b"cc_val".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn plaintextmac_write_read_round_trip() {
    let db = Db::open_internal_with_cipher(MemVfs::new(), KEK, PAGE, REALM, CipherId::PlaintextMac)
        .await
        .unwrap();
    let mut w = db.begin_write().await.unwrap();
    w.put(b"pt_key", b"pt_val").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"pt_key").await.unwrap().as_deref(),
        Some(b"pt_val".as_ref())
    );
}
