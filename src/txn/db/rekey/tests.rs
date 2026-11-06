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

#[path = "history_preflight_tests.rs"]
mod history_preflight_tests;

#[path = "rebuild_tests.rs"]
mod rebuild_tests;

#[path = "torn_chain_tests.rs"]
mod torn_chain_tests;

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
    db.evict_main_pages().unwrap();

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

/// Commit the same key twice with no retained history. That leaves the first
/// commit's leaf as a free page on disk. Return the ids the free chain names.
async fn store_with_a_free_page(options: OpenOptions) -> (MemVfs, Db<MemVfs>, Vec<u64>) {
    let vfs = MemVfs::new();
    let db = Db::open_internal_with_options(vfs.clone(), KEK0, PAGE, REALM, options)
        .await
        .unwrap();
    for value in [b"first".as_slice(), b"second".as_slice()] {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"kept", value).await.unwrap();
        txn.commit().await.unwrap();
    }
    let head = db.writer.lock().await.free_list_root_page_id;
    let (entries, _chain_pages) = crate::pager::freelist::read_chain(&db.pager, REALM, head)
        .await
        .unwrap();
    let free_pages: Vec<u64> = entries.iter().map(|&(_, page_id)| page_id).collect();
    assert!(!free_pages.is_empty(), "setup error: no free page on disk");
    (vfs, db, free_pages)
}

/// An aborted transaction draws free pages and writes other kinds over them in
/// the cache. A rekey after the abort must not fail against those discarded pages.
#[tokio::test(flavor = "current_thread")]
async fn rekey_after_abort_reseals_free_pages_from_disk() {
    use crate::pager::core::FileKey;

    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let (vfs, db, free_pages) = store_with_a_free_page(options.clone()).await;

    let mut aborted = db.begin_write().await.unwrap();
    aborted
        .put(b"overflowing", &vec![0xCD; PAGE * 4])
        .await
        .unwrap();
    let dirty = db
        .pager
        .inner
        .buffer_pool
        .lock()
        .dirty_for_file(FileKey::Main);
    assert!(
        free_pages.iter().all(|page_id| dirty.contains(page_id)),
        "setup error: the put did not draw every free page {free_pages:?}, dirty {dirty:?}"
    );
    aborted.abort().await;

    db.rekey_db(KEK0, 1)
        .await
        .expect("rekey succeeds after an aborted transaction");

    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"kept").await.unwrap().as_deref(),
        Some(b"second".as_slice())
    );
    assert_eq!(reader.get(b"overflowing").await.unwrap(), None);
    drop(reader);
    drop(db);

    let reopened = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options)
        .await
        .unwrap();
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"kept").await.unwrap().as_deref(),
        Some(b"second".as_slice())
    );
}

/// A crash mid-flush can tear a page the durable chain still names as free.
/// A later commit drew that page and never published. Free pages carry no data,
/// so a torn one cannot stop a rekey.
#[tokio::test(flavor = "current_thread")]
async fn rekey_succeeds_when_a_crash_tore_a_free_page() {
    use crate::vfs::{OpenMode, Vfs, VfsFile};

    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let (vfs, db, free_pages) = store_with_a_free_page(options.clone()).await;
    drop(db);

    // A tear keeps the leading bytes and replaces the rest, so the kind byte
    // survives and the tag fails.
    let torn_offset = free_pages[0] * PAGE as u64 + (PAGE / 2) as u64;
    let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    file.write_at(torn_offset, &[0xEE; PAGE / 2]).await.unwrap();
    file.sync().await.unwrap();
    drop(file);

    let db = Db::open_existing_with_options(vfs.clone(), KEK0, PAGE, REALM, options.clone())
        .await
        .expect("a torn free page leaves the store openable");
    db.rekey_db(KEK0, 1)
        .await
        .expect("rekey succeeds past a torn free page");
    drop(db);

    let reopened = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options)
        .await
        .expect("the store reopens after the rekey");
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"kept").await.unwrap().as_deref(),
        Some(b"second".as_slice())
    );
}

/// A registered reader can still reach this free page, so a tear is real corruption.
/// The rekey refuses, and the torn bytes stay on disk as evidence.
/// With the reader gone, a reopen finishes the rekey.
#[tokio::test(flavor = "current_thread")]
async fn rekey_refuses_a_torn_free_page_a_registered_reader_can_reach() {
    use crate::vfs::{OpenMode, Vfs, VfsFile};

    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded);
    let (vfs, db, free_pages) = store_with_a_free_page(options.clone()).await;
    let first = crate::CommitId(db.latest_commit().0 - 1);
    let reader = db.begin_read_at(first).await.unwrap();
    let torn_page = reader.root_page_id();
    assert!(
        free_pages.contains(&torn_page),
        "setup error: page {torn_page} is not among the free pages {free_pages:?}"
    );

    let torn_offset = torn_page * PAGE as u64 + (PAGE / 2) as u64;
    let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    file.write_at(torn_offset, &[0xEE; PAGE / 2]).await.unwrap();
    file.sync().await.unwrap();
    drop(file);
    db.evict_main_pages().unwrap();

    assert!(db.rekey_db(KEK0, 1).await.is_err());
    drop(reader);
    drop(db);

    let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    let mut tail = vec![0_u8; PAGE / 2];
    let read = file.read_at(torn_offset, &mut tail).await.unwrap();
    assert_eq!(read, PAGE / 2);
    assert_eq!(
        tail,
        vec![0xEE; PAGE / 2],
        "the torn bytes stay as evidence"
    );
    drop(file);

    let reopened = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options)
        .await
        .expect("no reader survives a reopen, so the resume finishes");
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"kept").await.unwrap().as_deref(),
        Some(b"second".as_slice())
    );
}

/// A crash can tear a free page while a rekey is in flight. The resume runs at
/// open from the durable intent. A torn page must not stop the open at any
/// boundary that still has a free-list pass ahead of it.
#[tokio::test(flavor = "current_thread")]
async fn rekey_resume_succeeds_past_a_torn_free_page() {
    use super::super::core::RekeyTestFault;
    use crate::vfs::{OpenMode, Vfs, VfsFile};

    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let boundaries = [
        RekeyTestFault::Intent,
        RekeyTestFault::MainPagesTargetReadable,
        RekeyTestFault::HeaderTargetPublished,
    ];
    for point in boundaries {
        let (vfs, db, free_pages) = store_with_a_free_page(options.clone()).await;
        db.interrupt_rekey_after(point);
        assert!(db.rekey_db(KEK0, 1).await.is_err(), "{point:?}");
        drop(db);

        let torn_offset = free_pages[0] * PAGE as u64 + (PAGE / 2) as u64;
        let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        file.write_at(torn_offset, &[0xEE; PAGE / 2]).await.unwrap();
        file.sync().await.unwrap();
        drop(file);

        let db = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options.clone())
            .await
            .unwrap_or_else(|error| panic!("{point:?}: the resume failed: {error:?}"));
        {
            let state = db.writer.lock().await;
            assert!(
                db.load_rekey_intent(&state).await.unwrap().is_none(),
                "{point:?}: the resumed rekey clears its durable intent"
            );
        }
        assert!(
            matches!(
                db.pager.mk_for(0, db.cipher_id),
                Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
            ),
            "{point:?}: a completed rekey retires the source epoch"
        );
        let reader = db.begin_read().await.unwrap();
        assert_eq!(
            reader.get(b"kept").await.unwrap().as_deref(),
            Some(b"second".as_slice()),
            "{point:?}"
        );
        drop(reader);
        let report = crate::recovery::deep_walk::run_deep_walk(&db)
            .await
            .unwrap();
        assert!(report.is_clean(), "{point:?}: deep walk report: {report:?}");
    }
}

/// A free page nothing can read gets a fresh blank page under the target epoch.
/// Its old plaintext does not move to the target key.
#[tokio::test(flavor = "current_thread")]
async fn rekey_blanks_free_pages_nothing_can_read() {
    use crate::pager::PageKind;
    use crate::vfs::{OpenMode, Vfs, VfsFile};

    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    let (vfs, db, free_pages) = store_with_a_free_page(options.clone()).await;
    db.rekey_db(KEK0, 1).await.unwrap();
    drop(db);

    let reopened = Db::open_existing_with_options(vfs.clone(), KEK0, PAGE, REALM, options)
        .await
        .unwrap();
    let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    for page_id in free_pages {
        let guard = reopened
            .pager
            .read_main_page(page_id, REALM, PageKind::Free)
            .await
            .unwrap();
        assert!(guard.body_ref().iter().all(|&byte| byte == 0));
        drop(guard);

        let mut envelope = [0u8; 12];
        file.read_at(page_id * PAGE as u64, &mut envelope)
            .await
            .unwrap();
        let sealed_epoch = u64::from_le_bytes(envelope[4..12].try_into().unwrap());
        assert_eq!(sealed_epoch, 1, "page {page_id} left the source epoch");
    }
}

/// A rekey frees the catalog pages its intent write supersedes.
/// A retained row at the latest commit still names them, so they keep their content.
#[tokio::test(flavor = "current_thread")]
async fn rekey_keeps_free_pages_a_retained_row_names() {
    let (vfs, db) = fresh_db().await;
    let first = {
        let mut tx = db.begin_write().await.unwrap();
        let mut counter = tx.counter("retained").unwrap();
        counter.set(1).await.unwrap();
        drop(counter);
        tx.commit().await.unwrap()
    };

    db.rekey_db(KEK0, 1).await.unwrap();
    drop(db);

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    let historical = reopened.begin_read_at(first).await.unwrap();
    assert!(matches!(
        historical.open_segment("absent").await,
        Err(PagedbError::NotFound)
    ));
}

/// Rows one draw commit writes. Its allocations exceed every free entry a scenario leaves.
const DRAW_ROWS: u32 = 64;
/// A value past the inline threshold that fits in one overflow page.
const DRAW_VALUE_LEN: usize = 3000;

struct RetainedRowScenario {
    label: &'static str,
    /// Retention for the commits before the reopen.
    before: RetainPolicy,
    /// Commits before the reopen. The newest is the row under test.
    commits: u64,
    /// Retention from the reopen onward, including across the rekey.
    after: RetainPolicy,
    /// Rewrite the rekey's tags to the latest commit and reopen before the draw.
    /// An earlier release left that tag on disk.
    old_release_tags: bool,
}

/// Rewrite the free chain in place, so `from` entries read `to`. The chain keeps
/// its pages and its head, so the durable header still names it.
async fn retag_free_chain(db: &Db<MemVfs>, from: u64, to: u64) {
    let head = db.writer.lock().await.free_list_root_page_id;
    let (entries, chain_pages) = crate::pager::freelist::read_chain(&db.pager, REALM, head)
        .await
        .unwrap();
    let retagged: Vec<(u64, u64)> = entries
        .into_iter()
        .map(|(tag, page_id)| (if tag == from { to } else { tag }, page_id))
        .collect();
    let rewritten_head = crate::pager::freelist::write::write_chain(
        &db.pager,
        REALM,
        PAGE,
        &chain_pages,
        &retagged,
        crate::pager::freelist::ChainTail::EMPTY,
    )
    .await
    .unwrap();
    assert_eq!(rewritten_head, head, "setup error: the chain head moved");
    db.pager.flush_main(REALM).await.unwrap();
}

async fn catalog_rows_of(
    db: &Db<MemVfs>,
    reader: &crate::ReadTxn<'_, MemVfs>,
) -> crate::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
    crate::btree::BTree::open(
        db.pager.clone(),
        db.realm_id,
        reader.catalog_root_page_id(),
        reader.next_page_id(),
        db.page_size,
    )
    .collect_batch_from(&[], 1024)
    .await
}

async fn free_entries_of(db: &Db<MemVfs>) -> Vec<(u64, u64)> {
    let head = db.writer.lock().await.free_list_root_page_id;
    crate::pager::freelist::read_chain(&db.pager, REALM, head)
        .await
        .unwrap()
        .0
}

/// The row reads its own values, or `CommitGone` reports it pruned. Anything else is the bug.
async fn assert_retained_row_reads_back(
    db: &Db<MemVfs>,
    label: &str,
    commit: crate::CommitId,
    catalog_rows: &[(bytes::Bytes, bytes::Bytes)],
    versioned: &[u8],
) {
    let reader = match db.begin_read_at(commit).await {
        Ok(reader) => reader,
        Err(PagedbError::CommitGone { .. }) => return,
        Err(error) => panic!("{label}: begin_read_at({commit:?}) failed: {error:?}"),
    };
    let read_catalog = catalog_rows_of(db, &reader)
        .await
        .unwrap_or_else(|error| panic!("{label}: the catalog at {commit:?} broke: {error:?}"));
    assert_eq!(
        read_catalog, catalog_rows,
        "{label}: the catalog at {commit:?} holds other rows"
    );
    assert_eq!(
        reader
            .get(b"versioned")
            .await
            .unwrap_or_else(|error| panic!("{label}: the data at {commit:?} broke: {error:?}"))
            .as_deref(),
        Some(versioned),
        "{label}: the data at {commit:?} holds another value"
    );
}

async fn run_retained_row_scenario(scenario: RetainedRowScenario) {
    let RetainedRowScenario {
        label,
        before,
        commits,
        after,
        old_release_tags,
    } = scenario;
    let vfs = MemVfs::new();
    let db = Db::open_internal_with_options(
        vfs.clone(),
        KEK0,
        PAGE,
        REALM,
        OpenOptions::default().with_commit_history_retain(before),
    )
    .await
    .unwrap();
    for index in 1..=commits {
        let mut tx = db.begin_write().await.unwrap();
        tx.put(b"versioned", &index.to_le_bytes()).await.unwrap();
        let mut counter = tx.counter("retained").unwrap();
        counter.set(index).await.unwrap();
        drop(counter);
        tx.commit().await.unwrap();
    }
    drop(db);

    let options = OpenOptions::default().with_commit_history_retain(after);
    let db = Db::open_existing_with_options(vfs.clone(), KEK0, PAGE, REALM, options.clone())
        .await
        .unwrap();
    let retained = db.latest_commit();
    let versioned = commits.to_le_bytes();

    // The published snapshot equals the retained row until the rekey moves the catalog root.
    let (row_catalog_pages, row_catalog_rows) = {
        let reader = db.begin_read().await.unwrap();
        let mut pages = std::collections::BTreeSet::new();
        crate::btree::BTree::open(
            db.pager.clone(),
            db.realm_id,
            reader.catalog_root_page_id(),
            reader.next_page_id(),
            db.page_size,
        )
        .collect_all_page_ids(&mut pages)
        .await
        .unwrap();
        let rows = catalog_rows_of(&db, &reader).await.unwrap();
        (pages, rows)
    };
    assert!(
        !row_catalog_rows.is_empty(),
        "setup error: {label}: the row at {retained:?} has an empty catalog"
    );

    db.rekey_db(KEK0, 1).await.unwrap();

    assert_eq!(
        db.latest_commit(),
        retained,
        "setup error: {label}: the rekey moved the latest commit"
    );
    let oldest = {
        let state = db.writer.lock().await;
        db.oldest_retained_history_commit(state.commit_history_root_page_id, state.next_page_id)
            .await
            .unwrap()
    };
    assert_eq!(
        oldest,
        Some(retained.0),
        "setup error: {label}: the row at {retained:?} is not the oldest row"
    );
    let rekey_tag = retained.0 + 1;
    let entries = free_entries_of(&db).await;
    let tagged_row_pages: Vec<u64> = row_catalog_pages
        .iter()
        .copied()
        .filter(|&page_id| entries.contains(&(rekey_tag, page_id)))
        .collect();
    assert!(
        !tagged_row_pages.is_empty(),
        "{label}: the rekey tagged no page the row names with {rekey_tag}, \
         row pages {row_catalog_pages:?}, free entries {entries:?}"
    );
    let (db, row_tag) = if old_release_tags {
        retag_free_chain(&db, rekey_tag, retained.0).await;
        drop(db);
        let reopened =
            Db::open_existing_with_options(vfs.clone(), KEK0, PAGE, REALM, options.clone())
                .await
                .unwrap();
        (reopened, retained.0)
    } else {
        (db, rekey_tag)
    };
    let cursor_before_draw = db.writer.lock().await.next_page_id;

    let drawing_commit = {
        let mut tx = db.begin_write().await.unwrap();
        for index in 0..DRAW_ROWS {
            tx.put(
                format!("draw-{index:03}").as_bytes(),
                &[0xDD; DRAW_VALUE_LEN],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap()
    };
    assert!(
        drawing_commit > retained,
        "setup error: {label}: the draw commit did not advance"
    );
    assert!(
        db.writer.lock().await.next_page_id > cursor_before_draw,
        "setup error: {label}: the commit did not exhaust the free pages it could draw"
    );
    let entries = free_entries_of(&db).await;
    assert!(
        tagged_row_pages
            .iter()
            .all(|&page_id| entries.contains(&(row_tag, page_id))),
        "{label}: the commit drew a page of {tagged_row_pages:?}, free entries {entries:?}"
    );

    if old_release_tags {
        assert!(
            db.begin_read_at(retained).await.is_ok(),
            "{label}: Count(2) keeps the row at {retained:?} through one draw"
        );
    }
    assert_retained_row_reads_back(&db, label, retained, &row_catalog_rows, &versioned).await;
    drop(db);

    let reopened = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options)
        .await
        .unwrap();
    assert_retained_row_reads_back(&reopened, label, retained, &row_catalog_rows, &versioned).await;
}

/// A rekey tags the catalog pages it supersedes with `L + 1`, where `L` is the latest commit.
/// Row `L` still names those pages.
/// The floor is `oldest + 1`, so the next commit cannot draw them while `L` is the oldest row.
///
/// `Count(1)` prunes row `L` in the next commit, so `CommitGone` is correct there.
/// The other scenarios keep row `L` through that commit, so it must read its own values.
#[tokio::test(flavor = "current_thread")]
async fn historical_read_after_a_rekey_survives_later_commits() {
    let scenarios = [
        RetainedRowScenario {
            label: "Count(1), the drawing commit prunes the row",
            before: RetainPolicy::Count(1),
            commits: 1,
            after: RetainPolicy::Count(1),
            old_release_tags: false,
        },
        RetainedRowScenario {
            label: "Count(2), one commit below retention",
            before: RetainPolicy::Count(2),
            commits: 1,
            after: RetainPolicy::Count(2),
            old_release_tags: false,
        },
        RetainedRowScenario {
            label: "Count(1) widened to Count(2) at a reopen",
            before: RetainPolicy::Count(1),
            commits: 3,
            after: RetainPolicy::Count(2),
            old_release_tags: false,
        },
        RetainedRowScenario {
            label: "Count(1) widened to Count(2), tags from an earlier release",
            before: RetainPolicy::Count(1),
            commits: 3,
            after: RetainPolicy::Count(2),
            old_release_tags: true,
        },
    ];
    for scenario in scenarios {
        run_retained_row_scenario(scenario).await;
    }
}

/// Pages each entry in the free chain names, split by whether `begin_write` put
/// them in the allocator cache.
async fn pages_tagged_with_oldest_row(db: &Db<MemVfs>) -> (Vec<u64>, Vec<u64>) {
    let oldest = {
        let state = db.writer.lock().await;
        db.oldest_retained_history_commit(state.commit_history_root_page_id, state.next_page_id)
            .await
            .unwrap()
            .expect("setup error: the store holds no row")
    };
    let tagged: Vec<u64> = free_entries_of(db)
        .await
        .into_iter()
        .filter(|&(tag, _)| tag == oldest)
        .map(|(_, page_id)| page_id)
        .collect();
    assert!(
        !tagged.is_empty(),
        "setup error: no free entry carries the tag {oldest}"
    );
    let txn = db.begin_write().await.unwrap();
    let cache = db.free_page_cache.lock().clone();
    txn.abort().await;
    (tagged, cache)
}

async fn store_past_its_retention(retain: u32, commits: u32) -> (MemVfs, Db<MemVfs>) {
    let vfs = MemVfs::new();
    let db = Db::open_internal_with_options(
        vfs.clone(),
        KEK0,
        PAGE,
        REALM,
        OpenOptions::default().with_commit_history_retain(RetainPolicy::Count(retain)),
    )
    .await
    .unwrap();
    for index in 0..commits {
        let mut tx = db.begin_write().await.unwrap();
        tx.put(b"versioned", &index.to_le_bytes()).await.unwrap();
        tx.commit().await.unwrap();
    }
    (vfs, db)
}

/// An ordinary commit's tag means only older rows reach the page. A store with
/// no rekey behind it reuses a page tagged with the oldest row, as it always did.
#[tokio::test(flavor = "current_thread")]
async fn a_never_rekeyed_store_reuses_a_page_tagged_with_the_oldest_row() {
    let (_vfs, db) = store_past_its_retention(2, 6).await;
    assert_eq!(db.mk_epoch.load(std::sync::atomic::Ordering::SeqCst), 0);

    let (tagged, cache) = pages_tagged_with_oldest_row(&db).await;

    assert!(
        tagged.iter().all(|page_id| cache.contains(page_id)),
        "pages {tagged:?} must be reusable, the allocator holds {cache:?}"
    );
}

/// A rekeyed store can hold a page its oldest row still reaches under that
/// row's own tag, so that tag stays out of the allocator.
#[tokio::test(flavor = "current_thread")]
async fn a_rekeyed_store_holds_back_a_page_tagged_with_the_oldest_row() {
    let (_vfs, db) = store_past_its_retention(2, 6).await;
    db.rekey_db(KEK0, 1).await.unwrap();

    let (tagged, cache) = pages_tagged_with_oldest_row(&db).await;

    assert!(
        tagged.iter().all(|page_id| !cache.contains(page_id)),
        "pages {tagged:?} must stay out of the allocator, which holds {cache:?}"
    );
}
