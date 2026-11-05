use std::sync::atomic::Ordering as AtomOrd;

use super::{FileKey, Pager, PagerConfig};
use crate::RealmId;
use crate::crypto::CipherId;
use crate::crypto::kdf::derive_mk;
use crate::errors::{CorruptionDetail, PagedbError};
use crate::pager::format::data_page::ENVELOPE_OVERHEAD;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;
use crate::vfs::memory::MemVfs;

const PAGE: usize = 4096;

async fn mk_pager() -> Pager<MemVfs> {
    mk_pager_on(MemVfs::new()).await
}

async fn mk_pager_on<V: Vfs>(vfs: V) -> Pager<V> {
    let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
    let cfg = PagerConfig {
        page_size: PAGE,
        buffer_pool_pages: 4,
        segment_cache_pages: 4,
        cipher_id: CipherId::Aes256Gcm,
        mk_epoch: 0,
        main_db_file_id: [0xAB; 16],
        main_db_path: "/main.db".into(),
        anchor_budget: 1_000_000,
        dek_lru_capacity: 16,
        observer_retry_count: 0,
        metrics_enabled: true,
    };
    Pager::open(vfs, mk, cfg).await.unwrap()
}

/// A read that misses before a write and finishes after it holds older bytes.
/// Those bytes cannot replace the dirty page, because the flush writes the
/// resident page under the dirty marker.
#[tokio::test(flavor = "current_thread")]
async fn read_miss_completing_after_a_write_keeps_the_dirty_page() {
    use crate::vfs::gated::{GatedVfs, bounded};

    const PAGE_ID: u64 = 10;
    let realm = RealmId([7; 16]);
    let older = vec![0x11u8; PAGE - ENVELOPE_OVERHEAD];
    let newer = vec![0x22u8; PAGE - ENVELOPE_OVERHEAD];

    let vfs = GatedVfs::new();
    let pager = mk_pager_on(vfs.clone()).await;
    pager
        .write_main_page(PAGE_ID, realm, PageKind::BTreeLeaf, &older)
        .await
        .unwrap();
    pager.flush_main(realm).await.unwrap();
    pager.evict_clean_main_pages().unwrap();

    let in_flight = vfs.park_next_read("/main.db", PAGE_ID * PAGE as u64);
    let racing_read = async {
        let guard = pager
            .read_main_page(PAGE_ID, realm, PageKind::BTreeLeaf)
            .await
            .unwrap();
        drop(guard);
    };
    let writer = async {
        in_flight.wait_until_parked().await;
        pager
            .write_main_page(PAGE_ID, realm, PageKind::BTreeLeaf, &newer)
            .await
            .unwrap();
        in_flight.release();
    };
    bounded(async { tokio::join!(racing_read, writer) }).await;

    pager.flush_main(realm).await.unwrap();
    pager.evict_clean_main_pages().unwrap();

    let guard = pager
        .read_main_page(PAGE_ID, realm, PageKind::BTreeLeaf)
        .await
        .unwrap();
    assert_eq!(
        &guard.body()[..16],
        &newer[..16],
        "the flush wrote the older bytes the racing read fetched"
    );
}

/// An open that starts before a main-file swap binds the old inode and
/// finishes after the swap. It runs again, so the new inode is the one cached.
#[tokio::test(flavor = "current_thread")]
async fn open_overlapping_a_main_swap_retries_on_the_new_inode() {
    use crate::vfs::gated::{GatedVfs, bounded};

    const PAGE_ID: u64 = 10;
    const NEW_IMAGE: &str = "/main.db.new";
    let realm = RealmId([7; 16]);
    let older = vec![0x11u8; PAGE - ENVELOPE_OVERHEAD];
    let newer = vec![0x22u8; PAGE - ENVELOPE_OVERHEAD];

    let vfs = GatedVfs::new();
    let pager = mk_pager_on(vfs.clone()).await;
    pager
        .write_main_page(PAGE_ID, realm, PageKind::BTreeLeaf, &older)
        .await
        .unwrap();
    pager.flush_main(realm).await.unwrap();
    pager
        .write_main_page(PAGE_ID, realm, PageKind::BTreeLeaf, &newer)
        .await
        .unwrap();
    pager.flush_main_to(realm, NEW_IMAGE).await.unwrap();
    pager.close_main_handle().await;
    pager.reset_main_pages().unwrap();

    let in_flight = vfs.park_next_open("/main.db");
    let racing_read = async {
        pager
            .read_main_page(PAGE_ID, realm, PageKind::BTreeLeaf)
            .await
            .unwrap()
            .body()
    };
    let swap = async {
        in_flight.wait_until_parked().await;
        pager.close_main_handle().await;
        vfs.rename(NEW_IMAGE, "/main.db").await.unwrap();
        pager.close_main_handle().await;
        pager.reset_main_pages().unwrap();
        in_flight.release();
    };
    let (racing_body, ()) = bounded(async { tokio::join!(racing_read, swap) }).await;
    assert_eq!(&racing_body[..16], &newer[..16]);

    pager.evict_clean_main_pages().unwrap();
    let guard = pager
        .read_main_page(PAGE_ID, realm, PageKind::BTreeLeaf)
        .await
        .unwrap();
    assert_eq!(
        &guard.body()[..16],
        &newer[..16],
        "the cached handle still names the replaced file"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn write_flush_read_round_trip_main() {
    let pager = mk_pager().await;
    let realm = RealmId([7; 16]);
    let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    body[..5].copy_from_slice(b"hello");
    pager
        .write_main_page(10, realm, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();
    pager.flush_main(realm).await.unwrap();
    // Drop cache by writing more pages than capacity.
    let blank = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    for p in 11..=20u64 {
        pager
            .write_main_page(p, realm, PageKind::BTreeLeaf, &blank)
            .await
            .unwrap();
    }
    pager.flush_main(realm).await.unwrap();

    let guard = pager
        .read_main_page(10, realm, PageKind::BTreeLeaf)
        .await
        .unwrap();
    let got = guard.body();
    assert_eq!(&got[..5], b"hello");
}

/// `read_main_node` must discover a node's kind from one physical read.
///
/// This locks the single-read shape of the API, not the B+ tree's
/// envelope/body agreement check — that check lives in
/// `BTree::read_node_guard` and is covered by the corruption regressions in
/// `tests/btree_basic.rs`. Kept separate on purpose: the agreement check is
/// only free because the authenticated kind arrives with the page, so if a
/// refactor reintroduces a second read here, the check stops being free and
/// this test is what says so.
#[tokio::test(flavor = "current_thread")]
async fn read_main_node_discovers_kind_in_a_single_read() {
    let pager = mk_pager().await;
    let realm = RealmId([1; 16]);
    let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    body[..4].copy_from_slice(b"node");
    pager
        .write_main_page(8, realm, PageKind::BTreeInternal, &body)
        .await
        .unwrap();
    pager.flush_main(realm).await.unwrap();
    pager
        .inner
        .buffer_pool
        .lock()
        .clear_file(FileKey::Main)
        .unwrap();
    let misses_before = pager.inner.buffer_pool_misses.load(AtomOrd::Relaxed);

    let (guard, kind) = pager.read_main_node(8, realm).await.unwrap();

    assert_eq!(kind, PageKind::BTreeInternal);
    assert_eq!(&guard.body_ref()[..4], b"node");
    assert_eq!(
        pager.inner.buffer_pool_misses.load(AtomOrd::Relaxed),
        misses_before + 1,
        "node-kind discovery must authenticate one cold-cache read"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn write_flush_read_round_trip_journal() {
    let pager = mk_pager().await;
    let realm = RealmId([7; 16]);
    let journal_id = [0x11; 16];
    let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    body[..6].copy_from_slice(b"segdat");
    pager
        .stage_journal_page(journal_id, 0, realm, &body)
        .await
        .unwrap();
    pager.flush_journal(journal_id, realm).await.unwrap();
    // Push other pages to evict.
    let blank = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    for page_id in 1..=10u64 {
        pager
            .stage_journal_page(journal_id, page_id, realm, &blank)
            .await
            .unwrap();
    }
    pager.flush_journal(journal_id, realm).await.unwrap();

    let guard = pager.read_journal_page(journal_id, 0, realm).await.unwrap();
    let got = guard.body();
    assert_eq!(&got[..6], b"segdat");
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_realm_read_fails_page_verification() {
    let pager = mk_pager().await;
    let realm_a = RealmId([1; 16]);
    let realm_b = RealmId([2; 16]);
    let mut body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    body[..3].copy_from_slice(b"abc");
    pager
        .write_main_page(5, realm_a, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();
    pager.flush_main(realm_a).await.unwrap();
    // Drop the cache entry.
    let blank = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    for p in 6..=20u64 {
        pager
            .write_main_page(p, realm_a, PageKind::BTreeLeaf, &blank)
            .await
            .unwrap();
    }
    pager.flush_main(realm_a).await.unwrap();
    let err = pager
        .read_main_page(5, realm_b, PageKind::BTreeLeaf)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            err,
            PagedbError::Corruption(CorruptionDetail::PageUnverifiable {
                realm_id,
                segment_id: None,
                page_id: 5,
                evictable: None,
            }) if realm_id == realm_b
        ),
        "cold cross-realm read must name the page that failed, got: {err:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cached_pages_require_an_exact_realm_match() {
    let pager = mk_pager().await;
    let zero_realm = RealmId([0; 16]);
    let nonzero_realm = RealmId([1; 16]);
    let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];

    pager
        .write_main_page(1, zero_realm, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();
    pager
        .write_main_page(2, nonzero_realm, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();

    {
        let mut cache = pager.inner.buffer_pool.lock();
        assert_eq!(
            cache
                .get((FileKey::Main, 1))
                .unwrap()
                .map(|page| page.realm_id_bytes),
            Some(Some(zero_realm.0))
        );
        assert_eq!(
            cache
                .get((FileKey::Main, 2))
                .unwrap()
                .map(|page| page.realm_id_bytes),
            Some(Some(nonzero_realm.0))
        );
    }

    for (page_id, requested_realm) in [(1, nonzero_realm), (2, zero_realm)] {
        let misses_before = pager.inner.buffer_pool_misses.load(AtomOrd::Relaxed);
        let cache_len_before = pager.inner.buffer_pool.lock().len();
        let err = pager
            .read_main_page(page_id, requested_realm, PageKind::BTreeLeaf)
            .await
            .err()
            .unwrap();

        assert!(matches!(err, PagedbError::ChecksumFailure));
        assert_eq!(
            pager.inner.buffer_pool_misses.load(AtomOrd::Relaxed),
            misses_before,
            "cached realm mismatch must not fall back to disk"
        );
        assert_eq!(pager.inner.buffer_pool.lock().len(), cache_len_before);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_illegal_page_kind_on_main() {
    let pager = mk_pager().await;
    let realm = RealmId([0; 16]);
    let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    let err = pager
        .write_main_page(1, realm, PageKind::SegmentData, &body)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, PagedbError::IllegalPageKind));
}

#[tokio::test(flavor = "current_thread")]
async fn body_size_enforced() {
    let pager = mk_pager().await;
    let realm = RealmId([0; 16]);
    // Too-small body.
    let small = vec![0u8; 10];
    let err = pager
        .write_main_page(1, realm, PageKind::BTreeLeaf, &small)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, PagedbError::PayloadTooLarge));
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn cache_class_isolation() {
    let pager = mk_pager().await;
    let realm = RealmId([3; 16]);
    let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    // Fill buffer_pool with 4 dirty main pages.
    for p in 1..=4u64 {
        pager
            .write_main_page(p, realm, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
    }
    // Hammer the segment cache with 8 journal pages. They go into
    // segment_cache, not buffer_pool, so main pages must remain dirty and intact.
    for page_id in 0..8u64 {
        pager
            .stage_journal_page([9; 16], page_id, realm, &body)
            .await
            .unwrap();
    }
    let dirty = pager.inner.buffer_pool.lock().dirty_for_file(FileKey::Main);
    assert_eq!(dirty.len(), 4);
}

/// Write and flush page 1, then read it back to learn its slab slot.
async fn flushed_page_slot(pager: &Pager<MemVfs>, realm: RealmId) -> usize {
    let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    pager
        .write_main_page(1, realm, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();
    pager.flush_main(realm).await.unwrap();
    let guard = pager
        .read_main_page(1, realm, PageKind::BTreeLeaf)
        .await
        .unwrap();
    guard.slot.expect("a cached page holds a slot")
}

#[tokio::test(flavor = "current_thread")]
async fn guard_held_across_flush_returns_pool_to_budget_on_release() {
    const BUDGET: usize = 4;
    let pager = mk_pager().await;
    let realm = RealmId([7; 16]);
    let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    for page_id in 1..=8u64 {
        pager
            .write_main_page(page_id, realm, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
    }
    let mut guards = Vec::new();
    for page_id in 1..=6u64 {
        guards.push(
            pager
                .read_main_page(page_id, realm, PageKind::BTreeLeaf)
                .await
                .unwrap(),
        );
    }

    pager.flush_main(realm).await.unwrap();

    assert_eq!(
        pager.inner.buffer_pool.lock().len(),
        6,
        "the flush evicts every unpinned page and spares the pinned ones"
    );

    // Each release past the budget evicts one entry.
    drop(guards.pop());
    assert_eq!(pager.inner.buffer_pool.lock().len(), 5);
    drop(guards.pop());
    assert_eq!(pager.inner.buffer_pool.lock().len(), BUDGET);
    guards.clear();

    let cache = pager.inner.buffer_pool.lock();
    assert_eq!(cache.len(), BUDGET);
    assert_eq!(cache.dirty_len(), 0);
    cache.check_usable().unwrap();
}

fn assert_dead_slot_fault(err: &PagedbError, expected_operation: &str, expected_slot: usize) {
    assert!(
        matches!(
            err,
            PagedbError::PageCacheStateInvalid {
                operation,
                detail: "slot holds no entry",
                slot: Some(slot),
            } if *operation == expected_operation && *slot == expected_slot
        ),
        "expected a dead-slot fault from {expected_operation}, got: {err:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn guard_drop_on_a_dead_slot_fails_the_next_read() {
    let pager = mk_pager().await;
    let realm = RealmId([7; 16]);
    let slot = flushed_page_slot(&pager, realm).await;

    let guard = pager
        .read_main_page(1, realm, PageKind::BTreeLeaf)
        .await
        .unwrap();
    pager.inner.buffer_pool.lock().clear_slot(slot);
    drop(guard);

    let err = pager
        .read_main_page(2, realm, PageKind::BTreeLeaf)
        .await
        .err()
        .unwrap();
    assert_dead_slot_fault(&err, "unpin_at", slot);
}

#[tokio::test(flavor = "current_thread")]
async fn discard_on_a_dead_slot_fails_the_next_flush() {
    let pager = mk_pager().await;
    let realm = RealmId([7; 16]);
    let slot = flushed_page_slot(&pager, realm).await;
    let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    pager
        .write_main_page(1, realm, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();

    pager.inner.buffer_pool.lock().clear_slot(slot);
    pager.discard_dirty_main();

    let err = pager.flush_main(realm).await.unwrap_err();
    assert_dead_slot_fault(&err, "discard_dirty", slot);
}

#[tokio::test(flavor = "current_thread")]
async fn latched_fault_fails_a_flush_with_nothing_dirty() {
    let pager = mk_pager().await;
    let realm = RealmId([7; 16]);
    let slot = flushed_page_slot(&pager, realm).await;
    assert_eq!(
        pager.inner.buffer_pool.lock().dirty_for_file(FileKey::Main),
        Vec::<u64>::new()
    );

    let guard = pager
        .read_main_page(1, realm, PageKind::BTreeLeaf)
        .await
        .unwrap();
    pager.inner.buffer_pool.lock().clear_slot(slot);
    drop(guard);

    let err = pager.flush_main(realm).await.unwrap_err();
    assert_dead_slot_fault(&err, "unpin_at", slot);
}

#[tokio::test(flavor = "current_thread")]
async fn dirty_page_missing_at_flush_is_a_typed_fault() {
    let pager = mk_pager().await;
    let realm = RealmId([7; 16]);
    let body = vec![0u8; PAGE - ENVELOPE_OVERHEAD];
    pager
        .write_main_page(1, realm, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();
    {
        let mut cache = pager.inner.buffer_pool.lock();
        cache.forget_key((FileKey::Main, 1));
    }

    let err = pager.flush_main(realm).await.unwrap_err();
    assert!(
        matches!(
            err,
            PagedbError::PageCacheStateInvalid {
                operation: "get_dirty",
                detail: "dirty page not resident",
                slot: None,
            }
        ),
        "got: {err:?}"
    );
}
