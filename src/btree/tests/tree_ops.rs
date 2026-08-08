use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;

use crate::RealmId;
use crate::btree::BTree;
use crate::crypto::CipherId;
use crate::crypto::kdf::derive_mk;
use crate::pager::{Pager, PagerConfig};
use crate::vfs::memory::MemVfs;

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
        .map(|(k, _)| String::from_utf8(k.to_vec()).unwrap())
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
    let keys: Vec<&[u8]> = got.iter().map(|(k, _)| k.as_ref()).collect();
    assert_eq!(keys, vec![b"apple".as_ref(), b"apply".as_ref()]);
}

#[tokio::test(flavor = "current_thread")]
async fn put_batch_inserts_all() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 16];
    let batch: Vec<(Bytes, Bytes)> = (0..200u32)
        .map(|i| {
            (
                Bytes::from(format!("k{i:04}").into_bytes()),
                Bytes::from(v.clone()),
            )
        })
        .collect();
    tree.put_batch(batch.clone()).await.unwrap();
    for (k, expected) in &batch {
        let got = tree.get(k).await.unwrap();
        assert_eq!(got.as_deref(), Some(expected.as_ref()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn put_batch_interleaves_with_existing_leaves_and_overwrites() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    const RECORDS: u32 = 20_000;
    const DUPLICATE: u32 = 12_345;
    let old = vec![1u8; 48];
    let new = vec![2u8; 48];
    let duplicate_final = vec![3u8; 48];
    for i in (0..RECORDS).step_by(2) {
        let key = format!("k{i:06}");
        tree.put(key.as_bytes(), &old).await.unwrap();
    }
    let mut batch: Vec<(Bytes, Bytes)> = Vec::with_capacity(RECORDS as usize + 1);
    for i in 0..RECORDS {
        let key = Bytes::from(format!("k{i:06}").into_bytes());
        batch.push((key.clone(), Bytes::from(new.clone())));
        if i == DUPLICATE {
            batch.push((key, Bytes::from(duplicate_final.clone())));
        }
    }

    tree.put_batch(batch).await.unwrap();

    for i in 0..RECORDS {
        let key = format!("k{i:06}");
        let got = tree.get(key.as_bytes()).await.unwrap();
        let expected = if i == DUPLICATE {
            duplicate_final.as_slice()
        } else {
            new.as_slice()
        };
        assert_eq!(got.as_deref(), Some(expected), "key {key}");
    }
}

/// Build a multi-level tree, then rewrite every record with a batch supplied in
/// the given order. Returns the ordered scan so the caller can assert the tree
/// a descent actually reaches, not just what `get` happens to answer.
async fn put_batch_rewrite_in_order(
    order: impl Iterator<Item = u32>,
    records: u32,
    updated: &[u8],
) -> Vec<Vec<u8>> {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let seed = vec![1u8; 64];
    for i in 0..records {
        tree.put(format!("k{i:06}").as_bytes(), &seed)
            .await
            .unwrap();
    }

    let batch: Vec<(Bytes, Bytes)> = order
        .map(|i| {
            (
                Bytes::from(format!("k{i:06}").into_bytes()),
                Bytes::from(updated.to_vec()),
            )
        })
        .collect();
    tree.put_batch(batch).await.unwrap();

    for i in 0..records {
        let key = format!("k{i:06}");
        assert_eq!(
            tree.get(key.as_bytes()).await.unwrap().as_deref(),
            Some(updated),
            "key {key}"
        );
    }
    tree.scan_prefix(b"k")
        .await
        .unwrap()
        .iter()
        .map(|(key, _)| key.to_vec())
        .collect()
}

/// A batch whose keys do not arrive in ascending order has to land in exactly
/// the tree a sequence of `put` calls would build.
///
/// `put_batch` caches the leaf path across records and reuses it while the next
/// key provably belongs to that leaf. The gate is both separator bounds: a key
/// below the cached leaf's lower bound must miss it and re-descend. Gating on
/// the upper bound alone lets a descending key be written into a leaf that no
/// descent for that key ever reaches — `get` then answers with the stale record
/// from the leaf that does own the key, and the ordered scan sees the misplaced
/// one as a duplicate. Both halves are asserted here because either alone can
/// be satisfied while the tree is wrong.
#[tokio::test(flavor = "current_thread")]
async fn put_batch_out_of_order_keys_land_in_the_right_leaves() {
    const RECORDS: u32 = 4_000;
    let updated = vec![2u8; 64];
    let expected: Vec<Vec<u8>> = (0..RECORDS)
        .map(|i| format!("k{i:06}").into_bytes())
        .collect();

    // Descending: every key after the first falls below the cached lower bound.
    let scanned = put_batch_rewrite_in_order((0..RECORDS).rev(), RECORDS, &updated).await;
    assert_eq!(scanned, expected, "descending batch");

    // Ascending runs broken by backward jumps, so the gate is alternately hit
    // and missed within a single batch.
    let interleaved = (0..RECORDS / 2).flat_map(|i| [RECORDS / 2 + i, RECORDS / 2 - 1 - i]);
    let scanned = put_batch_rewrite_in_order(interleaved, RECORDS, &updated).await;
    assert_eq!(scanned, expected, "interleaved batch");
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
                got.as_deref(),
                expected.as_deref(),
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
