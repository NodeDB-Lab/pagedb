//! Rekey integration tests: online re-encryption of main.db and segments.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, PagedbError, RealmId, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;
const KEK0: [u8; 32] = [0xAA; 32];
const REALM: RealmId = RealmId::new([0x01; 16]);

/// Open a fresh database at epoch 0.
async fn fresh_db() -> (MemVfs, Db<MemVfs>) {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    (vfs, db)
}

// ── Test 1 ─────────────────────────────────────────────────────────────────

/// After rekeying from epoch 0 to epoch 1, all keys inserted before the rekey
/// are still readable after reopening.
#[tokio::test(flavor = "current_thread")]
async fn rekey_main_db_only() {
    let (vfs, db) = fresh_db().await;

    // Write some data at epoch 0.
    {
        let mut tx = db.begin_write().await.unwrap();
        tx.put(b"alpha", b"value-alpha").await.unwrap();
        tx.put(b"beta", b"value-beta").await.unwrap();
        tx.put(b"gamma", b"value-gamma").await.unwrap();
        tx.commit().await.unwrap();
    }

    // Rekey to epoch 1.
    db.rekey_db(KEK0, 1).await.unwrap();

    // Reopen using epoch 1 credentials.
    drop(db);
    let db2 = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();

    // All keys must be readable.
    let rx = db2.begin_read().await.unwrap();
    assert_eq!(
        rx.get(b"alpha").await.unwrap().as_deref(),
        Some(b"value-alpha".as_slice())
    );
    assert_eq!(
        rx.get(b"beta").await.unwrap().as_deref(),
        Some(b"value-beta".as_slice())
    );
    assert_eq!(
        rx.get(b"gamma").await.unwrap().as_deref(),
        Some(b"value-gamma".as_slice())
    );
    drop(rx);
}

// ── Test 2 ─────────────────────────────────────────────────────────────────

/// Segments created at epoch 0 are rekeyed to epoch 1 and remain readable
/// afterwards. Footer mk_epoch reflects the new epoch.
#[tokio::test(flavor = "current_thread")]
async fn rekey_with_segments() {
    let (vfs, db) = fresh_db().await;

    // Create and seal two segments at epoch 0.
    let meta1 = {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"segment-1-page")
            .await
            .unwrap();
        let m = w.seal().await.unwrap();
        let mut tx = db.begin_write().await.unwrap();
        tx.link_segment("seg1", &m).await.unwrap();
        tx.commit().await.unwrap();
        m
    };
    let meta2 = {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"segment-2-page")
            .await
            .unwrap();
        let m = w.seal().await.unwrap();
        let mut tx = db.begin_write().await.unwrap();
        tx.link_segment("seg2", &m).await.unwrap();
        tx.commit().await.unwrap();
        m
    };

    assert_eq!(meta1.mk_epoch, 0);
    assert_eq!(meta2.mk_epoch, 0);

    // Rekey to epoch 1.
    db.rekey_db(KEK0, 1).await.unwrap();

    // Reopen.
    drop(db);
    let db2 = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();

    // Both segments must be readable.
    let r1 = db2.open_segment(REALM, "seg1").await.unwrap();
    let page = r1.read_page(1).await.unwrap();
    assert!(page.starts_with(b"segment-1-page"));
    // Footer mk_epoch should now be 1.
    assert_eq!(
        r1.meta().mk_epoch,
        1,
        "segment 1 should be epoch 1 after rekey"
    );

    let r2 = db2.open_segment(REALM, "seg2").await.unwrap();
    let page = r2.read_page(1).await.unwrap();
    assert!(page.starts_with(b"segment-2-page"));
    assert_eq!(
        r2.meta().mk_epoch,
        1,
        "segment 2 should be epoch 1 after rekey"
    );
}

// ── Test 3 ─────────────────────────────────────────────────────────────────

/// If rekey is interrupted after writing the watermark but before completing
/// the main-db rewrite, reopening must resume and complete the rekey.
#[tokio::test(flavor = "current_thread")]
async fn rekey_crash_mid_main_db() {
    let (vfs, db) = fresh_db().await;

    // Write data at epoch 0.
    {
        let mut tx = db.begin_write().await.unwrap();
        tx.put(b"key1", b"v1").await.unwrap();
        tx.put(b"key2", b"v2").await.unwrap();
        tx.commit().await.unwrap();
    }

    // Simulate a crash by writing a rekey watermark (main_db_done=false)
    // without actually rekeying any pages.
    db.inject_incomplete_rekey_watermark(1).await.unwrap();

    // Drop the Db and reopen — should auto-resume rekey to epoch 1.
    drop(db);
    let db2 = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();

    // Data must still be readable after resume.
    let rx = db2.begin_read().await.unwrap();
    assert_eq!(
        rx.get(b"key1").await.unwrap().as_deref(),
        Some(b"v1".as_slice())
    );
    assert_eq!(
        rx.get(b"key2").await.unwrap().as_deref(),
        Some(b"v2".as_slice())
    );
    drop(rx);
}

// ── Test 4 ─────────────────────────────────────────────────────────────────

/// A page sealed under epoch 0 must NOT be decryptable when its AAD claims
/// epoch 1. This validates that per-page epoch routing is actually enforced
/// by the AEAD binding.
#[tokio::test(flavor = "current_thread")]
async fn rekey_aad_misroute_across_epoch() {
    use pagedb::CipherId;
    use pagedb::crypto::aad::{Aad, AadFields, MAIN_DB_SEGMENT_ID};
    use pagedb::crypto::cipher::Cipher;
    use pagedb::crypto::kdf::{derive_dek, derive_mk};
    use pagedb::crypto::nonce::MainDbNonceGen;
    use pagedb::pager::format::data_page::{open_data_page, seal_data_page};
    use pagedb::pager::format::page_kind::PageKind;

    let file_id = [0xABu8; 16];
    let kek_salt = [0xCDu8; 16];

    // Derive epoch 0 and epoch 1 master keys from the same KEK.
    let mk0 = derive_mk(&KEK0, &kek_salt, 0).unwrap();
    let mk1 = derive_mk(&KEK0, &kek_salt, 1).unwrap();

    let realm = REALM;
    let dek0 = derive_dek(&mk0, realm).unwrap();
    let dek1 = derive_dek(&mk1, realm).unwrap();
    let cipher0 = Cipher::new_aes_gcm(&dek0);
    let cipher1 = Cipher::new_aes_gcm(&dek1);

    // Seal a page under epoch 0.
    let mut nonce_gen = MainDbNonceGen::new(&file_id, 1_000_000);
    let nonce = nonce_gen.next_nonce().unwrap();
    let page_id: u64 = 10;
    let aad0 = Aad::from_fields(AadFields {
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        page_kind: PageKind::BTreeLeaf.as_byte(),
        mk_epoch: 0,
        page_id,
        realm_id: realm,
        segment_id: MAIN_DB_SEGMENT_ID,
    });
    let mut buf = vec![0u8; PAGE];
    buf[24..29].copy_from_slice(b"hello");
    seal_data_page(&mut buf, PageKind::BTreeLeaf, 0, 0, &nonce, &aad0, &cipher0).unwrap();

    // Attempt to open with AAD claiming epoch 1 — must fail.
    let aad1 = Aad::from_fields(AadFields {
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        page_kind: PageKind::BTreeLeaf.as_byte(),
        mk_epoch: 1,
        page_id,
        realm_id: realm,
        segment_id: MAIN_DB_SEGMENT_ID,
    });
    let mut buf_clone = buf.clone();
    let err = open_data_page(&mut buf_clone, &aad1, &cipher1).unwrap_err();
    assert!(
        matches!(err, PagedbError::ChecksumFailure),
        "epoch-misrouted decrypt must fail with ChecksumFailure, got: {:?}",
        err
    );

    // Confirm that correct AAD (epoch 0 with epoch 0 key) succeeds.
    let mut buf_ok = buf.clone();
    open_data_page(&mut buf_ok, &aad0, &cipher0).unwrap();
}

// ── Test 5 ─────────────────────────────────────────────────────────────────

/// After a completed rekey, all data written at epoch 0 remains readable at
/// epoch 1 even for large trees that span multiple B+ tree nodes. This
/// verifies that the pager's epoch-routing path correctly handles mixed-epoch
/// pages that are in cache (populated by rekey_walk) vs pages read fresh.
#[tokio::test(flavor = "current_thread")]
async fn mixed_epoch_pages_readable() {
    let (vfs, db) = fresh_db().await;

    // Write enough data to guarantee multiple B+ tree pages.
    {
        let mut tx = db.begin_write().await.unwrap();
        for i in 0u32..64 {
            let key = format!("mixed-key-{:04}", i);
            let val = format!("mixed-val-{:04}", i);
            tx.put(key.as_bytes(), val.as_bytes()).await.unwrap();
        }
        tx.commit().await.unwrap();
    }

    // Perform the rekey.
    db.rekey_db(KEK0, 1).await.unwrap();

    // All data must be readable without reopening (in-memory epoch switch worked).
    let rx = db.begin_read().await.unwrap();
    for i in 0u32..64 {
        let key = format!("mixed-key-{:04}", i);
        let expected = format!("mixed-val-{:04}", i);
        let got = rx.get(key.as_bytes()).await.unwrap();
        assert_eq!(
            got.as_deref(),
            Some(expected.as_bytes()),
            "key {} missing after rekey",
            key
        );
    }
    drop(rx);

    // Also confirm the db reopens cleanly and data is persisted correctly.
    drop(db);
    let db2 = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    let rx2 = db2.begin_read().await.unwrap();
    for i in 0u32..64 {
        let key = format!("mixed-key-{:04}", i);
        let expected = format!("mixed-val-{:04}", i);
        let got = rx2.get(key.as_bytes()).await.unwrap();
        assert_eq!(
            got.as_deref(),
            Some(expected.as_bytes()),
            "key {} missing after reopen",
            key
        );
    }
    drop(rx2);
}
