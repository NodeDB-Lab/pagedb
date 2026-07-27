//! Regression: the overflow-chain walk (`collect_all_page_ids` /
//! `collect_overflow_chain`, and the strict `find_dangling` invariant helper)
//! must read a v2 overflow ROOT page's `next` pointer at the correct offset.
//!
//! A v2 root is laid out `refcount[4] || next[8] || …`; a chain page is
//! `next[8] || …`. Reading byte 0 uniformly decoded the root's `refcount` (1 for
//! a single-owner value) as the next page id, spuriously "chaining" to reserved
//! page 1 and failing AEAD — a false positive that looked like store corruption.
//!
//! A single-page overflow value (root only, `next = 0`, `refcount = 1`) is the
//! exact trigger. After a clean put of such a value, the walks must find NO
//! dangling pointer and must not read reserved pages.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::RealmId;
use crate::btree::BTree;
use crate::crypto::CipherId;
use crate::crypto::kdf::derive_mk;
use crate::pager::{Pager, PagerConfig};
use crate::vfs::memory::MemVfs;

const PAGE: usize = 4096;

async fn fresh_pager() -> Arc<Pager<MemVfs>> {
    let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
    let cfg = PagerConfig {
        page_size: PAGE,
        buffer_pool_pages: 64,
        segment_cache_pages: 64,
        cipher_id: CipherId::Aes256Gcm,
        mk_epoch: 0,
        main_db_file_id: [0xAB; 16],
        main_db_path: "/main.db".into(),
        anchor_budget: 1_000_000,
        dek_lru_capacity: 16,
        observer_retry_count: 0,
        metrics_enabled: true,
    };
    Arc::new(Pager::open(MemVfs::new(), mk, cfg).await.unwrap())
}

#[tokio::test(flavor = "current_thread")]
async fn single_page_overflow_root_walk_has_no_false_dangling() {
    let pager = fresh_pager().await;
    let mut tree = BTree::open(pager, RealmId::new([1; 16]), 0, 4, PAGE);

    // Value > inline threshold (page/4 = 1024) but <= root capacity (~4030),
    // so it stores as a SINGLE overflow root page: next = 0, refcount = 1.
    let value = vec![0xABu8; 2000];
    tree.put(b"k:single-page-overflow", &value).await.unwrap();
    tree.flush().await.unwrap();

    // The real value-read path round-trips exactly.
    let got = tree.get(b"k:single-page-overflow").await.unwrap();
    assert_eq!(got.as_deref(), Some(value.as_slice()), "value round-trips");

    // The strict structural walk must report the tree intact — NOT a spurious
    // "overflow chain -> RESERVED page 1".
    let dangling = tree.find_dangling().await;
    assert!(
        dangling.is_none(),
        "false-positive dangling on a clean single-page overflow value: {dangling:?}"
    );

    // And the reachable-page collection must not spuriously include page 1.
    let mut reachable = BTreeSet::new();
    tree.collect_all_page_ids(&mut reachable).await.unwrap();
    assert!(
        !reachable.contains(&1),
        "walk spuriously reached reserved page 1: {reachable:?}"
    );
}
