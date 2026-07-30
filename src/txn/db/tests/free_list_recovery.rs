//! A damaged free-list chain must cost reclaimable space, not the store.
//!
//! The free list records which pages may be reused. Every page it names is
//! already unreachable from every root, so the chain carries no data — losing
//! it leaks space until a full compaction rebuilds the file, and nothing more.
//! Treating it as fatal turned one damaged page into an unopenable store.

use crate::options::{OpenOptions, RetainPolicy};
use crate::vfs::memory::MemVfs;
use crate::{Db, RealmId};

const PAGE: usize = 4096;
const REALM: RealmId = RealmId::new([1u8; 16]);

async fn store() -> Db<MemVfs> {
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
    Db::open_internal_with_options(MemVfs::new(), [9u8; 32], PAGE, REALM, options)
        .await
        .expect("store must open")
}

/// A chain page whose declared entry count exceeds what the page can hold is
/// detached, and the data survives.
///
/// This is the observed real fault: the page authenticates as a `Free` page —
/// so nothing upstream rejects it — and only the count check inside the chain
/// header catches it. Reproduced by writing that exact page rather than by
/// pointing the root somewhere arbitrary, because an arbitrary page fails for a
/// different reason and would not exercise this path.
#[tokio::test(flavor = "current_thread")]
async fn an_unreadable_chain_is_detached_and_the_data_survives() {
    use crate::pager::format::data_page::body_capacity;
    use crate::pager::format::page_kind::PageKind;
    use crate::pager::freelist::layout::{ChainPageHeader, encode_chain_header};

    let db = store().await;
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"kept", b"value").await.unwrap();
        txn.commit().await.unwrap();
    }

    let root = {
        let mut state = db.writer.lock().await;
        let root = state.next_page_id;
        state.next_page_id += 1;
        state.free_list_root_page_id = root;
        root
    };

    let body_len = body_capacity(PAGE);
    let mut body = vec![0u8; body_len];
    encode_chain_header(
        &mut body,
        ChainPageHeader {
            next: 0,
            count: 0,
            suffix_entries: 0,
            suffix_max_cid: 0,
            suffix_min_cid: u64::MAX,
        },
    )
    .unwrap();
    // Declare more entries than the body can physically hold — the exact shape
    // a torn write leaves behind.
    let impossible = u32::try_from(body_len).unwrap();
    body[8..12].copy_from_slice(&impossible.to_le_bytes());
    db.pager
        .write_main_page(root, REALM, PageKind::Free, &body)
        .await
        .unwrap();

    db.drop_unreadable_free_list().await;

    assert_eq!(
        db.writer.lock().await.free_list_root_page_id,
        0,
        "an unreadable chain must be detached rather than left to fail every later read"
    );

    // The whole point: the store is still usable and still holds its data.
    let rtxn = db.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"kept").await.unwrap().as_deref(),
        Some(&b"value"[..]),
        "detaching the free list must not touch data reachable from the roots"
    );
    drop(rtxn);

    // And it still accepts writes — the allocator falls back to bump allocation.
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"after", b"ok").await.unwrap();
        txn.commit().await.unwrap();
    }
    let rtxn = db.begin_read().await.unwrap();
    assert_eq!(
        rtxn.get(b"after").await.unwrap().as_deref(),
        Some(&b"ok"[..])
    );
}

/// A readable chain must be left alone: this is a repair, not a reset.
#[tokio::test(flavor = "current_thread")]
async fn a_readable_chain_is_left_intact() {
    let db = store().await;
    // Write then delete so pages are freed and a chain actually exists.
    for i in 0..64u32 {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(format!("k{i}").as_bytes(), &[b'v'; 256])
            .await
            .unwrap();
        txn.commit().await.unwrap();
    }
    for i in 0..64u32 {
        let mut txn = db.begin_write().await.unwrap();
        txn.delete(format!("k{i}").as_bytes()).await.unwrap();
        txn.commit().await.unwrap();
    }

    let before = db.writer.lock().await.free_list_root_page_id;
    db.drop_unreadable_free_list().await;
    assert_eq!(
        db.writer.lock().await.free_list_root_page_id,
        before,
        "a chain that reads must survive the check untouched"
    );
}

/// An empty free list is not a damaged one.
#[tokio::test(flavor = "current_thread")]
async fn an_empty_chain_is_a_no_op() {
    let db = store().await;
    assert_eq!(db.writer.lock().await.free_list_root_page_id, 0);
    db.drop_unreadable_free_list().await;
    assert_eq!(db.writer.lock().await.free_list_root_page_id, 0);
}
