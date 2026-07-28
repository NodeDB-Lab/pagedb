//! Rekey integration tests: main-db and immutable-segment transitions.
//!
//! These live beside the implementation rather than in `tests/` because they
//! re-derive DEKs and re-open page envelopes directly to prove the epoch
//! transition rewrote what it claimed — key derivation and the page envelope
//! are both crate-internal.
#![allow(clippy::pedantic)]

use crate::options::RetainPolicy;
use crate::vfs::memory::MemVfs;
use crate::{
    Db, Evictable, OpenOptions, PagedbError, RealmId, RealmQuotas, SegmentKind, SegmentPageKind,
};

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

/// Rekey must rewrite roots named only by retained commit-history metadata
/// before the source epoch is retired.
#[tokio::test(flavor = "current_thread")]
async fn rekey_preserves_retained_historical_snapshots_after_reopen() {
    let vfs = MemVfs::new();
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded);
    let db = Db::open_internal_with_options(vfs.clone(), KEK0, PAGE, REALM, options)
        .await
        .unwrap();
    db.set_realm_quotas(
        REALM,
        RealmQuotas {
            max_pages: Some(10),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    let historical_large = vec![0xA5; PAGE * 3];
    let latest_large = vec![0x5A; PAGE * 2];

    let first = {
        let mut tx = db.begin_write().await.unwrap();
        for index in 0u16..256 {
            tx.put(
                format!("history-key-{index:04}").as_bytes(),
                &index.to_le_bytes(),
            )
            .await
            .unwrap();
        }
        tx.put(b"versioned", b"before-rekey").await.unwrap();
        tx.put(b"historical-overflow", &historical_large)
            .await
            .unwrap();
        tx.commit().await.unwrap()
    };
    db.set_realm_quotas(
        REALM,
        RealmQuotas {
            max_pages: Some(20),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    {
        let mut tx = db.begin_write().await.unwrap();
        tx.put(b"versioned", b"latest").await.unwrap();
        tx.put(b"historical-overflow", &latest_large).await.unwrap();
        tx.commit().await.unwrap();
    }

    db.rekey_db(KEK0, 1).await.unwrap();
    drop(db);

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    let historical = reopened.begin_read_at(first).await.unwrap();
    assert_eq!(
        historical.get(b"versioned").await.unwrap().as_deref(),
        Some(b"before-rekey".as_slice())
    );
    assert_eq!(
        historical
            .get(b"historical-overflow")
            .await
            .unwrap()
            .as_deref(),
        Some(historical_large.as_slice())
    );
    let first_index = 0u16.to_le_bytes();
    assert_eq!(
        historical
            .get(b"history-key-0000")
            .await
            .unwrap()
            .as_deref(),
        Some(first_index.as_slice())
    );
    assert!(matches!(
        historical.open_segment("absent").await,
        Err(PagedbError::NotFound)
    ));
    let latest = reopened.begin_read().await.unwrap();
    assert_eq!(
        latest.get(b"versioned").await.unwrap().as_deref(),
        Some(b"latest".as_slice())
    );
    assert_eq!(
        latest.get(b"historical-overflow").await.unwrap().as_deref(),
        Some(latest_large.as_slice())
    );
}

// ── Test 2 ─────────────────────────────────────────────────────────────────

/// Linked immutable segments are replaced under the target epoch while
/// preserving their logical payloads.
#[tokio::test(flavor = "current_thread")]
async fn rekey_with_segments() {
    let (_vfs, db) = fresh_db().await;

    // Create and seal two segments at epoch 0.
    let (meta1, extent) = {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"segment-1-data")
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Index, b"segment-1-index")
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Overflow, b"segment-1-overflow")
            .await
            .unwrap();
        let extent = w
            .append_extent(&[b"segment-1-extent-a", b"segment-1-extent-b"])
            .await
            .unwrap();
        w.set_manifest(b"segment-1-manifest").unwrap();
        let m = w.seal().await.unwrap();
        let mut tx = db.begin_write().await.unwrap();
        tx.link_segment("z-seg", &m).await.unwrap();
        tx.commit().await.unwrap();
        (m, extent)
    };
    let meta2 = {
        let mut w = db
            .create_segment(REALM, SegmentKind::Unspecified)
            .await
            .unwrap();
        w.append_page(SegmentPageKind::Data, b"segment-2-page")
            .await
            .unwrap();
        let mut m = w.seal().await.unwrap();
        m.evictable = Evictable::Replaceable;
        let mut tx = db.begin_write().await.unwrap();
        tx.link_segment("a-seg", &m).await.unwrap();
        tx.commit().await.unwrap();
        m
    };

    assert_eq!(meta1.mk_epoch, 0);
    assert_eq!(meta2.mk_epoch, 0);

    let old_txn = db.begin_read().await.unwrap();
    let old_reader = old_txn.open_segment("z-seg").await.unwrap();
    db.rekey_db(KEK0, 1).await.unwrap();

    assert!(
        old_reader
            .read_page(1)
            .await
            .unwrap()
            .starts_with(b"segment-1-data")
    );
    let r1 = db.open_segment(REALM, "z-seg").await.unwrap();
    assert!(
        r1.read_page(1)
            .await
            .unwrap()
            .starts_with(b"segment-1-data")
    );
    assert_eq!(r1.meta().mk_epoch, 1);
    assert!(
        r1.read_page(2)
            .await
            .unwrap()
            .starts_with(b"segment-1-index")
    );
    assert!(
        r1.read_page(3)
            .await
            .unwrap()
            .starts_with(b"segment-1-overflow")
    );
    let migrated_extent = r1.find_extent(extent.start_page_id).await.unwrap();
    assert!(migrated_extent[0].starts_with(b"segment-1-extent-a"));
    assert!(migrated_extent[1].starts_with(b"segment-1-extent-b"));
    let r2 = db.open_segment(REALM, "a-seg").await.unwrap();
    assert!(
        r2.read_page(1)
            .await
            .unwrap()
            .starts_with(b"segment-2-page")
    );
    assert_eq!(r2.meta().mk_epoch, 1);
    assert_eq!(r2.meta().evictable, Evictable::Replaceable);
    drop(r2);
    drop(r1);
    drop(old_reader);
    drop(old_txn);

    let gc = db.gc_now().await.unwrap();
    assert!(gc.reclaimed_segments >= 1);
}

/// A page sealed under epoch 0 must NOT be decryptable when its AAD claims
/// epoch 1. This validates that per-page epoch routing is actually enforced
/// by the AEAD binding.
#[tokio::test(flavor = "current_thread")]
async fn rekey_aad_misroute_across_epoch() {
    use crate::CipherId;
    use crate::crypto::aad::{Aad, AadFields, MAIN_DB_SEGMENT_ID};
    use crate::crypto::cipher::Cipher;
    use crate::crypto::kdf::{derive_dek, derive_mk};
    use crate::crypto::nonce::MainDbNonceGen;
    use crate::pager::format::data_page::{open_data_page, seal_data_page};
    use crate::pager::format::page_kind::PageKind;

    let file_id = [0xABu8; 16];
    let kek_salt = [0xCDu8; 16];

    // Derive epoch 0 and epoch 1 master keys from the same KEK.
    let mk0 = derive_mk(&KEK0, &kek_salt, 0).unwrap();
    let mk1 = derive_mk(&KEK0, &kek_salt, 1).unwrap();

    let realm = REALM;
    let dek0 = derive_dek(&mk0, realm, &file_id).unwrap();
    let dek1 = derive_dek(&mk1, realm, &file_id).unwrap();
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

/// An existing reader keeps its pinned logical snapshot even after rekey
/// rewrites durable main-db pages and clean cache entries are evicted.
#[tokio::test(flavor = "current_thread")]
async fn rekey_preserves_preexisting_main_reader_snapshot_after_cache_evict() {
    let (_vfs, db) = fresh_db().await;
    let old_large_value = vec![0xA5; PAGE];
    {
        let mut tx = db.begin_write().await.unwrap();
        tx.put(b"versioned", b"before").await.unwrap();
        tx.put(b"large", &old_large_value).await.unwrap();
        tx.commit().await.unwrap();
    }

    let reader = db.begin_read().await.unwrap();
    {
        let mut tx = db.begin_write().await.unwrap();
        tx.put(b"versioned", b"after").await.unwrap();
        tx.put(b"large", b"replacement").await.unwrap();
        tx.commit().await.unwrap();
    }

    db.rekey_db(KEK0, 1).await.unwrap();
    db.evict_main_pages(REALM);

    assert_eq!(
        reader.get(b"versioned").await.unwrap().as_deref(),
        Some(b"before".as_slice())
    );
    assert_eq!(
        reader.get(b"large").await.unwrap().as_deref(),
        Some(old_large_value.as_slice())
    );
}

/// Rekey must re-encrypt the durable free-list chain and every reusable page
/// it names; otherwise physical integrity checks cannot authenticate those
/// pages after the source epoch is retired.
#[tokio::test(flavor = "current_thread")]
async fn rekey_preserves_durable_free_list_across_reopen() {
    let vfs = MemVfs::new();
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = Db::open_internal_with_options(vfs.clone(), KEK0, PAGE, REALM, options.clone())
        .await
        .unwrap();
    let mut insert = db.begin_write().await.unwrap();
    for index in 0..300_u32 {
        insert
            .put(format!("free-{index:05}").as_bytes(), &[0x7A; 128])
            .await
            .unwrap();
    }
    insert.commit().await.unwrap();
    let mut delete = db.begin_write().await.unwrap();
    for index in 0..250_u32 {
        delete
            .delete(format!("free-{index:05}").as_bytes())
            .await
            .unwrap();
    }
    delete.commit().await.unwrap();
    assert!(db.stats().await.unwrap().free_list_pending_entries > 0);

    db.rekey_db(KEK0, 1).await.unwrap();
    drop(db);

    let reopened = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options)
        .await
        .unwrap();
    assert!(reopened.stats().await.unwrap().free_list_pending_entries > 0);
    let report = crate::recovery::deep_walk::run_deep_walk(&reopened)
        .await
        .unwrap();
    assert!(report.is_clean(), "free-list rekey report: {report:?}");
}

/// Epochs are monotonic. Rejecting the current or an older epoch must leave
/// the live store usable and must not persist a rekey intent.
#[tokio::test(flavor = "current_thread")]
async fn rekey_rejects_non_advancing_epoch() {
    let (vfs, db) = fresh_db().await;
    {
        let mut tx = db.begin_write().await.unwrap();
        tx.put(b"stable", b"value").await.unwrap();
        tx.commit().await.unwrap();
    }

    assert!(matches!(
        db.rekey_db(KEK0, 0).await,
        Err(PagedbError::RekeyStateInvalid { .. })
    ));
    assert_eq!(
        db.begin_read()
            .await
            .unwrap()
            .get(b"stable")
            .await
            .unwrap()
            .as_deref(),
        Some(b"value".as_slice())
    );

    db.rekey_db(KEK0, 2).await.unwrap();
    assert!(matches!(
        db.rekey_db(KEK0, 1).await,
        Err(PagedbError::RekeyStateInvalid { .. })
    ));
    drop(db);

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    assert_eq!(
        reopened
            .begin_read()
            .await
            .unwrap()
            .get(b"stable")
            .await
            .unwrap()
            .as_deref(),
        Some(b"value".as_slice())
    );
}

/// A catalog too large to fit one page must be re-sealed in full.
///
/// The catalog is the one reader-visible root that cannot be re-sealed before
/// the target header is published — it carries the intent that admits recovery
/// from a stale header. Only the pages a rekey happens to write through get
/// re-sealed by that write, so a catalog spanning several pages is where a
/// missing catalog traversal shows up: everything off the written path stays
/// sealed under an epoch that retirement then destroys.
fn counter_name(index: u32) -> String {
    // Long names on purpose: the catalog must span more pages than any single
    // copy-on-write path through it touches.
    format!("catalog-counter-{index:05}-{}", "n".repeat(200))
}

#[tokio::test(flavor = "current_thread")]
async fn rekey_reseals_a_catalog_larger_than_one_page() {
    let vfs = MemVfs::new();
    // Retention disabled on purpose: with history retained, the newest retained
    // row names the live catalog root, so the retained-root walk re-seals the
    // catalog incidentally and hides whether the rekey covers it on its own.
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let db = Db::open_internal_with_options(vfs.clone(), KEK0, PAGE, REALM, options.clone())
        .await
        .unwrap();

    // Enough counter rows to push the catalog tree past a single page.
    {
        let mut tx = db.begin_write().await.unwrap();
        for index in 0..400_u32 {
            let mut counter = tx.counter(&counter_name(index)).unwrap();
            counter.set(u64::from(index) + 1).await.unwrap();
            drop(counter);
        }
        tx.commit().await.unwrap();
    }
    let catalog_pages_before = db.stats().await.unwrap().main_db_next_page_id;
    assert!(
        catalog_pages_before > 8,
        "test setup must build a multi-page catalog, got {catalog_pages_before} pages"
    );

    db.rekey_db(KEK0, 1).await.unwrap();
    drop(db);

    let reopened = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options)
        .await
        .unwrap();
    let report = crate::recovery::deep_walk::run_deep_walk(&reopened)
        .await
        .unwrap();
    assert!(
        report.is_clean(),
        "multi-page catalog rekey report: {report:?}"
    );

    // Every counter must still decode under the target epoch.
    let mut tx = reopened.begin_write().await.unwrap();
    for index in [0_u32, 199, 399] {
        let counter = tx.counter(&counter_name(index)).unwrap();
        assert_eq!(counter.get().await.unwrap(), u64::from(index) + 1);
        drop(counter);
    }
    tx.commit().await.unwrap();
}

/// Rekey must not abandon the pages its own catalog transitions supersede.
///
/// Each durable stage rewrites the catalog copy-on-write. Without routing the
/// superseded pages onto the free list they are unreachable from every root and
/// absent from the free list — a permanent leak that grows with every rekey,
/// and one the source epoch's retirement makes unauthenticatable.
#[tokio::test(flavor = "current_thread")]
async fn rekey_leaves_no_leaked_pages() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    {
        let mut tx = db.begin_write().await.unwrap();
        for index in 0..200_u32 {
            tx.put(format!("leak-{index:05}").as_bytes(), &[0x5C; 96])
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
    }

    for epoch in 1..=3_u64 {
        db.rekey_db(KEK0, epoch).await.unwrap();
    }
    drop(db);

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    let report = crate::recovery::deep_walk::run_deep_walk(&reopened)
        .await
        .unwrap();
    assert!(report.is_clean(), "repeated rekey report: {report:?}");
    assert!(
        report.orphan_page_ids.is_empty(),
        "rekey leaked {} pages: {:?}",
        report.orphan_page_ids.len(),
        report.orphan_page_ids
    );
}
