use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use pagedb::btree::BTree;
use pagedb::btree::internal::Internal;
use pagedb::btree::leaf::{Leaf, LeafValue};
use pagedb::btree::node::body_capacity;
use pagedb::btree::overflow::encode_overflow;
use pagedb::crypto::CipherId;
use pagedb::crypto::kdf::derive_mk;
use pagedb::errors::CorruptionDetail;
use pagedb::pager::{PageKind, Pager, PagerConfig};
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

async fn tree_with_unreadable_overflow_root(
    pager: Arc<Pager<MemVfs>>,
    key: &[u8],
    leaf_page_id: u64,
    overflow_root_page_id: u64,
) -> BTree<MemVfs> {
    let realm = RealmId::new([1; 16]);
    let mut leaf = Leaf::new();
    leaf.upsert(
        key,
        LeafValue::Overflow {
            total_len: (PAGE * 2) as u64,
            root_page_id: overflow_root_page_id,
        },
    );
    let mut leaf_body = vec![0u8; body_capacity(PAGE)];
    leaf.encode(&mut leaf_body).unwrap();
    pager
        .write_main_page(leaf_page_id, realm, PageKind::BTreeLeaf, &leaf_body)
        .await
        .unwrap();

    // Deliberately seal the referenced root under the chain-page kind. The
    // leaf remains readable, but releasing its old overflow value must fail.
    let mut overflow_body = vec![0u8; body_capacity(PAGE)];
    encode_overflow(&mut overflow_body, 0, b"old").unwrap();
    pager
        .write_main_page(
            overflow_root_page_id,
            realm,
            PageKind::Overflow,
            &overflow_body,
        )
        .await
        .unwrap();

    BTree::open(pager, realm, leaf_page_id, overflow_root_page_id + 1, PAGE)
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
async fn collect_all_returns_every_key_including_the_top_of_the_keyspace() {
    // Keys are arbitrary byte strings: there is no reserved sentinel and no
    // length ceiling, so no concrete upper bound is outside the valid domain.
    // `collect_all` must therefore be unbounded — a range scan against any
    // invented maximum would silently drop the keys asserted here.
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    let v = vec![0u8; 16];
    for i in 0..200u32 {
        tree.put(format!("k{i:04}").as_bytes(), &v).await.unwrap();
    }
    // The exact sentinel a bounded scan would have used, and a key extending it.
    tree.put(&[0xFF; 256], &v).await.unwrap();
    let mut beyond = vec![0xFFu8; 256];
    beyond.push(0x00);
    tree.put(&beyond, &v).await.unwrap();

    let all = tree.collect_all().await.unwrap();
    assert_eq!(all.len(), 202);
    let keys: Vec<&[u8]> = all.iter().map(|(k, _)| k.as_slice()).collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]), "not ascending");
    assert_eq!(keys[200], &[0xFF; 256]);
    assert_eq!(keys[201], beyond.as_slice());
}

#[tokio::test(flavor = "current_thread")]
async fn collect_all_on_empty_tree_is_empty() {
    let pager = fresh_pager().await;
    let tree = fresh_tree(pager);
    assert!(tree.collect_all().await.unwrap().is_empty());
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
    // Cache invalidation forces a fresh rightmost descent; append must still
    // compare against the tree's actual maximum key.
    let error = tree.put_append(b"b00", b"v").await.unwrap_err();
    assert!(matches!(error, PagedbError::AppendNotMonotonic));
    tree.put_append(b"z99", b"v").await.unwrap();
    // Now further appends must be > "z99".
    assert!(tree.put_append(b"z00", b"v").await.is_err());
    tree.put_append(b"zzz", b"v").await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn read_node_rejects_authenticated_envelope_body_kind_mismatch() {
    let pager = fresh_pager().await;
    let realm = RealmId::new([1; 16]);

    let mut leaf = Leaf::new();
    leaf.upsert(b"k", LeafValue::Inline(b"v".to_vec()));
    let mut leaf_body = vec![0u8; body_capacity(PAGE)];
    leaf.encode(&mut leaf_body).unwrap();

    let child_leaf_page_id = 62;
    pager
        .write_main_page(child_leaf_page_id, realm, PageKind::BTreeLeaf, &leaf_body)
        .await
        .unwrap();

    let internal = Internal {
        leftmost_child: child_leaf_page_id,
        entries: Vec::new(),
    };
    let mut internal_body = vec![0u8; body_capacity(PAGE)];
    internal.encode(&mut internal_body).unwrap();

    for (page_id, envelope_kind, body) in [
        (61, PageKind::BTreeLeaf, internal_body.as_slice()),
        (64, PageKind::BTreeInternal, leaf_body.as_slice()),
    ] {
        pager
            .write_main_page(page_id, realm, envelope_kind, body)
            .await
            .unwrap();
        let tree = BTree::open(pager.clone(), realm, page_id, 65, PAGE);
        let error = tree
            .get(b"k")
            .await
            .expect_err("authenticated envelope and decoded node kinds must agree");

        assert!(matches!(
            error,
            PagedbError::Corruption(CorruptionDetail::NodeKindMismatch {
                page_id: Some(_),
                ..
            })
        ));
    }
}

/// A page reaches the decoder already authenticated, so its bytes are whatever
/// a key holder wrote — not necessarily what a correct writer would write. The
/// node header's `prefix_len` and `slot_count`, and every slot-directory entry,
/// are used directly as slice indices; unvalidated, a malformed value panics
/// the library instead of reporting corruption. Each case below panicked before
/// the body was structurally validated at parse time.
#[tokio::test(flavor = "current_thread")]
async fn malformed_node_body_reports_corruption_instead_of_panicking() {
    use pagedb::btree::node::{HEADER_LEN, NodeKind, write_header, write_slot_offset};

    let capacity = body_capacity(PAGE);

    // prefix_len far past the body: the prefix slice alone runs off the end.
    let mut oversized_prefix = vec![0u8; capacity];
    write_header(&mut oversized_prefix, NodeKind::Leaf, 1, 60_000, 0, 0);

    // Slot directory extends past the body.
    let mut oversized_directory = vec![0u8; capacity];
    write_header(&mut oversized_directory, NodeKind::Leaf, 60_000, 0, 0, 0);

    // Directory fits, but a slot points at an offset outside the body.
    let mut wild_slot = vec![0u8; capacity];
    write_header(&mut wild_slot, NodeKind::Leaf, 1, 0, 0, 0);
    write_slot_offset(&mut wild_slot, 0, 0, u16::MAX);

    // Slot points just inside the body, but the record it describes overruns it.
    let mut truncated_record = vec![0u8; capacity];
    write_header(&mut truncated_record, NodeKind::Leaf, 1, 0, 0, 0);
    let record_offset = capacity - 4;
    write_slot_offset(&mut truncated_record, 0, 0, record_offset as u16);
    truncated_record[record_offset..record_offset + 2].copy_from_slice(&600u16.to_le_bytes());

    // Same class on the internal-node record layout.
    let mut wild_internal = vec![0u8; capacity];
    write_header(&mut wild_internal, NodeKind::Internal, 1, 0, 0, 0);
    write_slot_offset(&mut wild_internal, 0, 0, (capacity - 3) as u16);

    let cases: [(&str, Vec<u8>, PageKind); 5] = [
        (
            "prefix_len past body",
            oversized_prefix,
            PageKind::BTreeLeaf,
        ),
        (
            "slot directory past body",
            oversized_directory,
            PageKind::BTreeLeaf,
        ),
        ("slot offset past body", wild_slot, PageKind::BTreeLeaf),
        (
            "record overruns body",
            truncated_record,
            PageKind::BTreeLeaf,
        ),
        (
            "internal record overruns body",
            wild_internal,
            PageKind::BTreeInternal,
        ),
    ];

    let pager = fresh_pager().await;
    let realm = RealmId::new([1; 16]);
    for (index, (label, body, envelope_kind)) in cases.into_iter().enumerate() {
        let page_id = 80 + index as u64;
        assert!(body.len() > HEADER_LEN);
        pager
            .write_main_page(page_id, realm, envelope_kind, &body)
            .await
            .unwrap();
        let tree = BTree::open(pager.clone(), realm, page_id, page_id + 1, PAGE);

        let error = tree.get(b"k").await.expect_err(label);
        assert!(
            matches!(
                error,
                PagedbError::Corruption(CorruptionDetail::NodeBodyMalformed { .. })
            ),
            "{label}: expected NodeBodyMalformed, got {error:?}"
        );
    }
}

#[test]
fn delete_range_rejects_leaf_sibling_cycle_without_hanging() {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let pager = fresh_pager().await;
            let realm = RealmId::new([1; 16]);
            let leaf_page_id = 31;

            let mut leaf = Leaf::new();
            leaf.right_sibling = leaf_page_id;
            leaf.upsert(b"k", LeafValue::Inline(b"v".to_vec()));
            let mut body = vec![0u8; body_capacity(PAGE)];
            leaf.encode(&mut body).unwrap();
            pager
                .write_main_page(leaf_page_id, realm, PageKind::BTreeLeaf, &body)
                .await
                .unwrap();

            let mut tree = BTree::open(pager, realm, leaf_page_id, 32, PAGE);
            tree.delete_range(b"a", b"z").await.map(|_| ())
        });
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("delete_range sibling-cycle detection should return before the timeout");
    let error = result.expect_err("leaf sibling cycles must not be accepted");
    assert!(matches!(error, PagedbError::Corruption(_)));
}

#[test]
fn get_rejects_internal_child_cycle_without_hanging() {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let pager = fresh_pager().await;
            let realm = RealmId::new([1; 16]);
            let root_page_id = 41;
            let internal = Internal {
                leftmost_child: root_page_id,
                entries: Vec::new(),
            };
            let mut body = vec![0u8; body_capacity(PAGE)];
            internal.encode(&mut body).unwrap();
            pager
                .write_main_page(root_page_id, realm, PageKind::BTreeInternal, &body)
                .await
                .unwrap();
            let tree = BTree::open(pager, realm, root_page_id, 42, PAGE);
            tree.get(b"k").await.map(|_| ())
        });
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("get internal-cycle detection should return before the timeout");
    let error = result.expect_err("internal child cycles must not be accepted");
    assert!(matches!(error, PagedbError::Corruption(_)));
}

#[test]
fn put_rejects_internal_child_cycle_without_hanging() {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let pager = fresh_pager().await;
            let realm = RealmId::new([1; 16]);
            let root_page_id = 43;
            let internal = Internal {
                leftmost_child: root_page_id,
                entries: Vec::new(),
            };
            let mut body = vec![0u8; body_capacity(PAGE)];
            internal.encode(&mut body).unwrap();
            pager
                .write_main_page(root_page_id, realm, PageKind::BTreeInternal, &body)
                .await
                .unwrap();
            let mut tree = BTree::open(pager, realm, root_page_id, 44, PAGE);
            tree.put(b"k", b"v").await
        });
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("put internal-cycle detection should return before the timeout");
    let error = result.expect_err("internal child cycles must not be accepted");
    assert!(matches!(error, PagedbError::Corruption(_)));
}

#[test]
fn bulk_load_rejects_separator_that_cannot_fit_without_hanging() {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let pager = fresh_pager().await;
            let mut tree = fresh_tree(pager);
            let key_len = body_capacity(PAGE) - 32;
            tree.bulk_load(vec![
                (vec![b'a'; key_len], Vec::new()),
                (vec![b'b'; key_len], Vec::new()),
            ])
            .await
        });
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("bulk_load separator validation should return before the timeout");
    let error = result.expect_err("oversize internal separators must be rejected");
    assert!(matches!(error, PagedbError::PayloadTooLarge));
}

#[tokio::test(flavor = "current_thread")]
async fn bulk_load_rejects_non_strict_key_order_without_poisoning_tree() {
    let cases = [
        vec![
            (b"b".to_vec(), b"two".to_vec()),
            (b"a".to_vec(), b"one".to_vec()),
        ],
        vec![
            (b"a".to_vec(), b"one".to_vec()),
            (b"a".to_vec(), b"two".to_vec()),
        ],
    ];

    for pairs in cases {
        let pager = fresh_pager().await;
        let mut tree = fresh_tree(pager);
        let error = tree
            .bulk_load(pairs)
            .await
            .expect_err("bulk_load must reject unsorted or duplicate keys");
        assert!(
            matches!(error, PagedbError::Io(ref io) if io.kind() == std::io::ErrorKind::InvalidInput)
        );
        assert_eq!(tree.root_page_id(), 0);
        assert_eq!(tree.next_page_id(), 4);

        tree.bulk_load(vec![
            (b"a".to_vec(), b"one".to_vec()),
            (b"b".to_vec(), b"two".to_vec()),
        ])
        .await
        .unwrap();
        assert_eq!(
            tree.get(b"a").await.unwrap().as_deref(),
            Some(b"one".as_ref())
        );
        assert_eq!(
            tree.get(b"b").await.unwrap().as_deref(),
            Some(b"two".as_ref())
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn put_rejects_oversized_key_without_poisoning_tree() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    tree.put(b"small", b"value").await.unwrap();

    let oversized_key = vec![b'z'; body_capacity(PAGE)];
    let error = tree
        .put(&oversized_key, b"bad")
        .await
        .expect_err("oversized keys must be rejected at put time");
    assert!(matches!(error, PagedbError::PayloadTooLarge));
    assert_eq!(
        tree.get(b"small").await.unwrap().as_deref(),
        Some(b"value".as_ref())
    );
    assert!(tree.get(&oversized_key).await.unwrap().is_none());
    tree.put(b"valid", b"good").await.unwrap();
    tree.flush().await.unwrap();
    assert_eq!(
        tree.get(b"valid").await.unwrap().as_deref(),
        Some(b"good".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn put_append_rejects_oversized_key_without_poisoning_tree() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);
    tree.put_append(b"small", b"value").await.unwrap();

    let oversized_key = vec![b'z'; body_capacity(PAGE)];
    let error = tree
        .put_append(&oversized_key, b"bad")
        .await
        .expect_err("append mode must reject oversized keys at put time");
    assert!(matches!(error, PagedbError::PayloadTooLarge));
    assert_eq!(
        tree.get(b"small").await.unwrap().as_deref(),
        Some(b"value".as_ref())
    );
    assert!(tree.get(&oversized_key).await.unwrap().is_none());
    tree.put_append(b"valid", b"good").await.unwrap();
    tree.flush().await.unwrap();
    assert_eq!(
        tree.get(b"valid").await.unwrap().as_deref(),
        Some(b"good".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn put_release_failure_does_not_publish_replacement() {
    let pager = fresh_pager().await;
    let mut tree = tree_with_unreadable_overflow_root(pager, b"k", 80, 81).await;

    let error = tree
        .put(b"k", b"new")
        .await
        .expect_err("replacing an unreadable overflow value must fail");
    assert!(matches!(
        error,
        PagedbError::ChecksumFailure | PagedbError::Corruption(_) | PagedbError::Io(_)
    ));
    match tree.get(b"k").await {
        Err(PagedbError::ChecksumFailure | PagedbError::Corruption(_) | PagedbError::Io(_)) => {}
        Ok(Some(value)) => panic!("failed replacement published value {value:?}"),
        Ok(None) => panic!("failed replacement removed the original key"),
        Err(error) => panic!("unexpected post-failure read error: {error:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn delete_release_failure_does_not_remove_key() {
    let pager = fresh_pager().await;
    let mut tree = tree_with_unreadable_overflow_root(pager, b"k", 90, 91).await;

    let error = tree
        .delete(b"k")
        .await
        .expect_err("deleting an unreadable overflow value must fail");
    assert!(matches!(
        error,
        PagedbError::ChecksumFailure | PagedbError::Corruption(_) | PagedbError::Io(_)
    ));
    match tree.get(b"k").await {
        Err(PagedbError::ChecksumFailure | PagedbError::Corruption(_) | PagedbError::Io(_))
        | Ok(Some(_)) => {}
        Ok(None) => panic!("failed delete removed the original key"),
        Err(error) => panic!("unexpected post-failure read error: {error:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn delete_range_visits_fresh_split_leaves_before_flush() {
    let pager = fresh_pager().await;
    let mut tree = fresh_tree(pager);

    for i in 0..2_000u32 {
        let key = format!("k{i:08}");
        let value = format!("v-{i:08}-").repeat(8);
        tree.put(key.as_bytes(), value.as_bytes()).await.unwrap();
    }

    let deleted = tree.delete_range(b"k00000500", b"k00001500").await.unwrap();
    assert_eq!(deleted, 1_000);

    for i in 0..2_000u32 {
        let key = format!("k{i:08}");
        let got = tree.get(key.as_bytes()).await.unwrap();
        if (500..1_500).contains(&i) {
            assert!(got.is_none(), "key {key} should have been deleted");
        } else {
            assert!(got.is_some(), "key {key} should remain visible");
        }
    }
}
