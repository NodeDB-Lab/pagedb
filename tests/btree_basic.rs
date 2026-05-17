use std::sync::Arc;

use pagedb::btree::BTree;
use pagedb::crypto::CipherId;
use pagedb::crypto::kdf::derive_mk;
use pagedb::pager::{Pager, PagerConfig};
use pagedb::vfs::memory::MemVfs;
use pagedb::{PagedbError, RealmId};

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

fn fresh_tree(pager: Arc<Pager<MemVfs>>) -> BTree<MemVfs> {
    BTree::open(pager, RealmId::new([1; 16]), 0, 4, PAGE)
}

#[tokio::test(flavor = "current_thread")]
async fn empty_tree_get_returns_none() {
    let pager = fresh_pager().await;
    let tree = fresh_tree(pager);
    assert!(tree.get(b"missing").await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn put_get_round_trip() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    tree.put(b"key1", b"value1").await.unwrap();
    assert_eq!(
        tree.get(b"key1").await.unwrap().as_deref(),
        Some(b"value1".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn update_overwrites() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    tree.put(b"k", b"v1").await.unwrap();
    tree.put(b"k", b"v2").await.unwrap();
    assert_eq!(
        tree.get(b"k").await.unwrap().as_deref(),
        Some(b"v2".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn delete_works() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    tree.put(b"k", b"v").await.unwrap();
    assert!(tree.delete(b"k").await.unwrap());
    assert!(tree.get(b"k").await.unwrap().is_none());
    assert!(!tree.delete(b"k").await.unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn many_keys_single_leaf() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    for i in 0..10u8 {
        let key = [b'k', i];
        let val = vec![i; 16];
        tree.put(&key, &val).await.unwrap();
    }
    for i in 0..10u8 {
        let key = [b'k', i];
        let got = tree.get(&key).await.unwrap().unwrap();
        assert_eq!(got, vec![i; 16]);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn forces_leaf_split() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    // Each value is ~256 bytes; many entries force a leaf split.
    let big = vec![0xAA; 256];
    for i in 0..32u32 {
        let key = format!("key{i:04}");
        tree.put(key.as_bytes(), &big).await.unwrap();
    }
    for i in 0..32u32 {
        let key = format!("key{i:04}");
        let got = tree.get(key.as_bytes()).await.unwrap();
        assert_eq!(got.as_deref(), Some(big.as_slice()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn multi_level_tree() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    // Insert 500 keys with ~64-byte values — forces 2+ levels.
    let v = vec![0xCC; 64];
    for i in 0..500u32 {
        let key = format!("k{i:08}");
        tree.put(key.as_bytes(), &v).await.unwrap();
    }
    for i in 0..500u32 {
        let key = format!("k{i:08}");
        let got = tree.get(key.as_bytes()).await.unwrap();
        assert_eq!(got.as_deref(), Some(v.as_slice()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn forward_scan_returns_sorted() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 16];
    // Insert in reverse order; scan must return sorted.
    for i in (0..50u32).rev() {
        let key = format!("k{i:04}");
        tree.put(key.as_bytes(), &v).await.unwrap();
    }
    let got = tree.collect_range(b"k0010", b"k0020").await.unwrap();
    let keys: Vec<String> = got
        .into_iter()
        .map(|(k, _)| String::from_utf8(k).unwrap())
        .collect();
    let expected: Vec<String> = (10..20).map(|i| format!("k{i:04}")).collect();
    assert_eq!(keys, expected);
}

#[tokio::test(flavor = "current_thread")]
async fn large_value_stored_via_overflow() {
    // G2: values exceeding page_size/4 are stored as overflow chains rather
    // than rejected. Verify round-trip correctness.
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let huge = vec![0xABu8; PAGE / 4 + 1];
    tree.put(b"k", &huge).await.unwrap();
    let got = tree.get(b"k").await.unwrap();
    assert_eq!(got.as_deref(), Some(huge.as_slice()));
}

#[tokio::test(flavor = "current_thread")]
async fn persistence_round_trip() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager.clone());
    let v = vec![0xEE; 32];
    for i in 0..100u32 {
        let key = format!("k{i:04}");
        tree.put(key.as_bytes(), &v).await.unwrap();
    }
    tree.flush().await.unwrap();
    let root = tree.root_page_id();
    let next = tree.next_page_id();
    drop(tree);

    let reopened = BTree::open(pager, RealmId::new([1; 16]), root, next, PAGE);
    for i in 0..100u32 {
        let key = format!("k{i:04}");
        let got = reopened.get(key.as_bytes()).await.unwrap();
        assert_eq!(got.as_deref(), Some(v.as_slice()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cross_realm_read_fails() {
    let pager = fresh_pager().await;
    let realm_a = RealmId::new([1; 16]);
    let realm_b = RealmId::new([2; 16]);
    let mut tree_a = BTree::open(pager.clone(), realm_a, 0, 4, PAGE);
    tree_a.put(b"k", b"v").await.unwrap();
    tree_a.flush().await.unwrap();
    let root = tree_a.root_page_id();

    let tree_b = BTree::open(pager, realm_b, root, 100, PAGE);
    let err = tree_b.get(b"k").await.err().unwrap();
    assert!(matches!(err, PagedbError::ChecksumFailure));
}

#[tokio::test(flavor = "current_thread")]
async fn put_append_inserts_monotonic_keys() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    // Sorted keys with values; sized so multiple leaves are produced.
    for i in 0..2_000u32 {
        let key = format!("k{i:08}");
        let value = format!("v-{i}").repeat(8);
        tree.put_append(key.as_bytes(), value.as_bytes())
            .await
            .unwrap();
    }
    tree.flush().await.unwrap();
    // Spot-check a few; full scan would be slow but get() exercises descent.
    for i in [0, 1, 7, 100, 999, 1_500, 1_999] {
        let key = format!("k{i:08}");
        let expected = format!("v-{i}").repeat(8);
        let got = tree.get(key.as_bytes()).await.unwrap();
        assert_eq!(got.as_deref(), Some(expected.as_bytes()), "key {key}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn put_append_rejects_non_monotonic() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    tree.put_append(b"k001", b"v").await.unwrap();
    tree.put_append(b"k002", b"v").await.unwrap();
    let err = tree.put_append(b"k001", b"v").await.err().unwrap();
    assert!(matches!(err, PagedbError::AppendNotMonotonic));
    // Equal also rejected.
    let err = tree.put_append(b"k002", b"v").await.err().unwrap();
    assert!(matches!(err, PagedbError::AppendNotMonotonic));
}

#[tokio::test(flavor = "current_thread")]
async fn put_append_after_regular_put_re_descends() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    tree.put_append(b"a01", b"v").await.unwrap();
    tree.put_append(b"a02", b"v").await.unwrap();
    // Regular put may target any leaf — invalidates the append cache and
    // resets the monotonic tracker.
    tree.put(b"middle", b"v").await.unwrap();
    // After invalidation, put_append accepts any key (cache reset).
    tree.put_append(b"z99", b"v").await.unwrap();
    // Now further appends must be > "z99".
    assert!(tree.put_append(b"z00", b"v").await.is_err());
    tree.put_append(b"zzz", b"v").await.unwrap();
}
