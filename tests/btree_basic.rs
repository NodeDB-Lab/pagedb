use std::sync::Arc;

use pagedb::btree::BTree;
use pagedb::btree::internal::Internal;
use pagedb::btree::leaf::{Leaf, LeafValue};
use pagedb::btree::node::body_capacity;
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
    // After invalidation, put_append accepts any key (cache reset).
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
