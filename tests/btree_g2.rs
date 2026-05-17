use std::collections::BTreeMap;
use std::sync::Arc;

use pagedb::RealmId;
use pagedb::btree::BTree;
use pagedb::crypto::CipherId;
use pagedb::crypto::kdf::derive_mk;
use pagedb::pager::{Pager, PagerConfig};
use pagedb::vfs::memory::MemVfs;

const PAGE: usize = 4096;

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn gen_range(&mut self, max: u64) -> u64 {
        self.next() % max
    }
}

async fn fresh_pager() -> Arc<Pager<MemVfs>> {
    let mk = derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
    let cfg = PagerConfig {
        page_size: PAGE,
        buffer_pool_pages: 256,
        segment_cache_pages: 16,
        cipher_id: CipherId::Aes256Gcm,
        mk_epoch: 0,
        main_db_file_id: [0xAB; 16],
        main_db_path: "/main.db".into(),
        anchor_budget: 100_000_000,
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
async fn prefix_compression_shrinks_keyspace() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let prefix = b"long-shared-prefix-12345678/";
    for i in 0..50u32 {
        let mut key = prefix.to_vec();
        key.extend_from_slice(format!("{i:04}").as_bytes());
        tree.put(&key, &[0u8; 32]).await.unwrap();
    }
    for i in 0..50u32 {
        let mut key = prefix.to_vec();
        key.extend_from_slice(format!("{i:04}").as_bytes());
        let got = tree.get(&key).await.unwrap();
        assert_eq!(got.as_deref(), Some([0u8; 32].as_ref()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn monotonic_insert_uses_90_10_split() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 64];
    for i in 0..500u32 {
        let key = format!("k{i:06}");
        tree.put(key.as_bytes(), &v).await.unwrap();
    }
    for i in 0..500u32 {
        let key = format!("k{i:06}");
        let got = tree.get(key.as_bytes()).await.unwrap();
        assert_eq!(got.as_deref(), Some(v.as_slice()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn scan_rev_returns_descending() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 8];
    for i in 0..50u32 {
        let key = format!("k{i:04}");
        tree.put(key.as_bytes(), &v).await.unwrap();
    }
    let got = tree.scan_rev(b"k0010", b"k0020").await.unwrap();
    let keys: Vec<String> = got
        .into_iter()
        .map(|(k, _)| String::from_utf8(k).unwrap())
        .collect();
    let expected: Vec<String> = (10..20).rev().map(|i| format!("k{i:04}")).collect();
    assert_eq!(keys, expected);
}

#[tokio::test(flavor = "current_thread")]
async fn scan_prefix_short_circuits() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 8];
    for word in ["apple", "apply", "apricot", "banana", "cherry"] {
        tree.put(word.as_bytes(), &v).await.unwrap();
    }
    let got = tree.scan_prefix(b"app").await.unwrap();
    let keys: Vec<&[u8]> = got.iter().map(|(k, _)| k.as_slice()).collect();
    assert_eq!(keys, vec![b"apple".as_ref(), b"apply".as_ref()]);
}

#[tokio::test(flavor = "current_thread")]
async fn put_batch_inserts_all() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 16];
    let batch: Vec<(Vec<u8>, Vec<u8>)> = (0..200u32)
        .map(|i| (format!("k{i:04}").into_bytes(), v.clone()))
        .collect();
    tree.put_batch(batch.clone()).await.unwrap();
    for (k, expected) in &batch {
        let got = tree.get(k).await.unwrap();
        assert_eq!(got.as_deref(), Some(expected.as_slice()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn delete_batch_removes_all() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 16];
    for i in 0..100u32 {
        let key = format!("k{i:04}");
        tree.put(key.as_bytes(), &v).await.unwrap();
    }
    let to_del: Vec<Vec<u8>> = (0..100u32)
        .step_by(2)
        .map(|i| format!("k{i:04}").into_bytes())
        .collect();
    tree.delete_batch(to_del.clone()).await.unwrap();
    for i in 0..100u32 {
        let key = format!("k{i:04}");
        let got = tree.get(key.as_bytes()).await.unwrap();
        if i % 2 == 0 {
            assert!(got.is_none(), "expected deleted: {key}");
        } else {
            assert_eq!(got.as_deref(), Some(v.as_slice()));
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn delete_range_returns_count() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 32];
    for i in 0..100u32 {
        let key = format!("k{i:04}");
        tree.put(key.as_bytes(), &v).await.unwrap();
    }
    let n = tree.delete_range(b"k0030", b"k0060").await.unwrap();
    assert_eq!(n, 30);
    for i in 0..100u32 {
        let key = format!("k{i:04}");
        let got = tree.get(key.as_bytes()).await.unwrap();
        if (30..60).contains(&i) {
            assert!(got.is_none());
        } else {
            assert_eq!(got.as_deref(), Some(v.as_slice()));
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn overflow_value_round_trip() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    // page_size/4 = 1024 on 4 KiB; overflow at >1024.
    let big: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    tree.put(b"big-key", &big).await.unwrap();
    let got = tree.get(b"big-key").await.unwrap();
    assert_eq!(got.as_deref(), Some(big.as_slice()));
    // Overwrite with a small value; old chain should be freed.
    tree.put(b"big-key", b"tiny").await.unwrap();
    let got = tree.get(b"big-key").await.unwrap();
    assert_eq!(got.as_deref(), Some(b"tiny".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn overflow_persistence_round_trip() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager.clone());
    let big: Vec<u8> = (0..8192).map(|i| (i % 17) as u8).collect();
    tree.put(b"key", &big).await.unwrap();
    tree.flush().await.unwrap();
    let root = tree.root_page_id();
    let next = tree.next_page_id();
    drop(tree);

    let reopened = BTree::open(pager, RealmId::new([1; 16]), root, next, PAGE);
    let got = reopened.get(b"key").await.unwrap();
    assert_eq!(got.as_deref(), Some(big.as_slice()));
}

#[tokio::test(flavor = "current_thread")]
async fn random_100k_ops_match_ground_truth() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager.clone());
    let mut truth: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut rng = SplitMix64::new(0xDEAD_BEEF_CAFE_F00D);

    for op in 0..100_000u32 {
        let op_kind = rng.gen_range(100);
        let key_idx = rng.gen_range(2000);
        let key = format!("k{key_idx:06}").into_bytes();
        if op_kind < 60 {
            let vlen = (rng.gen_range(96) + 1) as usize;
            let value: Vec<u8> = (0..vlen).map(|_| rng.next() as u8).collect();
            tree.put(&key, &value).await.unwrap();
            truth.insert(key, value);
        } else if op_kind < 90 {
            let got = tree.get(&key).await.unwrap();
            let expected = truth.get(&key).cloned();
            assert_eq!(
                got,
                expected,
                "op {op} key {:?}",
                String::from_utf8_lossy(&key)
            );
        } else {
            let removed = tree.delete(&key).await.unwrap();
            let had = truth.remove(&key).is_some();
            assert_eq!(removed, had, "op {op}");
        }
        if (op + 1) % 25_000 == 0 {
            tree.flush().await.unwrap();
            let root = tree.root_page_id();
            let next = tree.next_page_id();
            let reopened = BTree::open(pager.clone(), RealmId::new([1; 16]), root, next, PAGE);
            for (k, v) in &truth {
                let got = reopened.get(k).await.unwrap_or_else(|e| {
                    panic!("get failed for key {:?}: {e}", String::from_utf8_lossy(k));
                });
                assert_eq!(
                    got.as_deref(),
                    Some(v.as_slice()),
                    "value mismatch for key {:?}",
                    String::from_utf8_lossy(k)
                );
            }
            tree = reopened;
        }
    }
}
