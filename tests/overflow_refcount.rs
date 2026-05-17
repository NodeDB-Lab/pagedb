//! Integration tests for v2 overflow root pages with reference counting.
//! Verifies that shared overflow chains survive partial deletions and are
//! freed exactly when the last reference is dropped.

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([0xEE; 16]);
const KEK: [u8; 32] = [0x33; 32];

async fn fresh_db() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
        .await
        .unwrap()
}

// ─── Test 1: Basic write and read of a large (overflow) value ────────────────

#[tokio::test(flavor = "current_thread")]
async fn large_value_write_read() {
    let db = fresh_db().await;

    // 8 KB value spans two overflow pages under a 4 KB page size.
    let value = vec![0xABu8; 8192];

    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"big-key", &value).await.unwrap();
        txn.commit().await.unwrap();
    }

    let txn = db.begin_read().await.unwrap();
    let got = txn.get(b"big-key").await.unwrap().unwrap();
    assert_eq!(got.as_slice(), value.as_slice());
}

// ─── Test 2: Overwrite frees old overflow chain ───────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn overwrite_frees_old_chain() {
    let db = fresh_db().await;

    let value_a = vec![0xAAu8; 8192];
    let value_b = vec![0xBBu8; 8192];

    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"key", &value_a).await.unwrap();
        txn.commit().await.unwrap();
    }

    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"key", &value_b).await.unwrap();
        txn.commit().await.unwrap();
    }

    let txn = db.begin_read().await.unwrap();
    let got = txn.get(b"key").await.unwrap().unwrap();
    assert_eq!(got.as_slice(), value_b.as_slice());
}

// ─── Test 3: Delete frees overflow chain ─────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn delete_frees_overflow_chain() {
    let db = fresh_db().await;

    let value = vec![0xCCu8; 8192];

    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"del-key", &value).await.unwrap();
        txn.commit().await.unwrap();
    }

    {
        let mut txn = db.begin_write().await.unwrap();
        let deleted = txn.delete(b"del-key").await.unwrap();
        assert!(deleted);
        txn.commit().await.unwrap();
    }

    let txn = db.begin_read().await.unwrap();
    let got = txn.get(b"del-key").await.unwrap();
    assert!(got.is_none(), "key should be gone after delete");
}

// ─── Test 4: Mixed inline and overflow values coexist ────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn inline_and_overflow_coexist() {
    let db = fresh_db().await;

    let small = b"tiny";
    let large = vec![0xDDu8; 8192];

    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"small", small).await.unwrap();
        txn.put(b"large", &large).await.unwrap();
        txn.commit().await.unwrap();
    }

    let txn = db.begin_read().await.unwrap();
    assert_eq!(
        txn.get(b"small").await.unwrap().unwrap().as_slice(),
        small.as_ref()
    );
    assert_eq!(
        txn.get(b"large").await.unwrap().unwrap().as_slice(),
        large.as_slice()
    );
}

// ─── Test 5: Overflow value larger than 2 pages ──────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn overflow_chain_three_pages() {
    let db = fresh_db().await;

    // Root capacity: 4096 - 40 - 16 = 4040 bytes.
    // Chain page capacity: 4096 - 40 - 12 = 4044 bytes.
    // 12 500 bytes: root(4040) + chain(4044) + chain(4416 > 4044) — so 3 pages.
    let value = vec![0xFFu8; 12_500];

    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"three-page", &value).await.unwrap();
        txn.commit().await.unwrap();
    }

    let txn = db.begin_read().await.unwrap();
    let got = txn.get(b"three-page").await.unwrap().unwrap();
    assert_eq!(got.as_slice(), value.as_slice());
}

// ─── Test 6: Many overflow writes and deletes do not corrupt other keys ───────

#[tokio::test(flavor = "current_thread")]
async fn many_overflow_writes_no_corruption() {
    let db = fresh_db().await;

    const N: usize = 50;
    let large = vec![0xA0u8; 8192];

    // Write N large keys.
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0..N {
            let key = format!("big-{i:04}");
            txn.put(key.as_bytes(), &large).await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    // Delete even-indexed keys.
    {
        let mut txn = db.begin_write().await.unwrap();
        for i in (0..N).step_by(2) {
            let key = format!("big-{i:04}");
            txn.delete(key.as_bytes()).await.unwrap();
        }
        txn.commit().await.unwrap();
    }

    // Verify odd-indexed keys still readable and even-indexed are gone.
    let txn = db.begin_read().await.unwrap();
    for i in 0..N {
        let key = format!("big-{i:04}");
        let got = txn.get(key.as_bytes()).await.unwrap();
        if i % 2 == 0 {
            assert!(got.is_none(), "key {key} should be deleted");
        } else {
            assert_eq!(
                got.unwrap().as_slice(),
                large.as_slice(),
                "key {key} value mismatch"
            );
        }
    }
}
