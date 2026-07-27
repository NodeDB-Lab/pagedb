//! The durable free list is loaded and rewritten one bounded window at a time.
//! These cover what that windowing can get wrong: losing the retained tail
//! across the splice, handing one page id to two structures because the entry
//! deleting it was never scanned, stranding below-floor entries deeper than the
//! window ever reaches, and under-counting the reader-stall backlog because
//! only the window is resident.

use std::collections::BTreeSet;

use crate::options::RetainPolicy;
use crate::pager::freelist::{WINDOW_PAGES, read_chain, read_chain_prefix, write_chain};
use crate::vfs::memory::MemVfs;
use crate::{Db, OpenOptions, PagedbError, ReaderStallPolicy, RealmId};

const KEK: [u8; 32] = [0x5Au8; 32];
const REALM: RealmId = RealmId::new([0x5Bu8; 16]);
const PAGE: usize = 4096;

async fn open_with(options: OpenOptions) -> Db<MemVfs> {
    Db::open_internal_with_options(MemVfs::new(), KEK, PAGE, REALM, options)
        .await
        .unwrap()
}

/// A hand-laid chain segment and the page ids it accounts for.
struct LaidChain {
    head: u64,
    /// Pages the chain itself occupies.
    hosts: Vec<u64>,
    /// Pages the chain records as free.
    named: Vec<u64>,
    /// First page id past everything this segment used.
    next_free_id: u64,
}

impl LaidChain {
    fn accounted(&self) -> BTreeSet<u64> {
        self.hosts
            .iter()
            .chain(self.named.iter())
            .copied()
            .collect()
    }
}

/// Lay `pages` chain pages from `base`, each carrying `entries_per_page`
/// entries tagged `freed_at`, with the last page linked to `tail`.
///
/// Laid page by page rather than through `rewrite_chain` on purpose: a repacked
/// chain is dense, and a dense chain is exactly the shape that hides whether
/// the window ever advances. A real store accumulates sparse pages, and those
/// are what strand entries beyond the window.
async fn lay_chain(
    db: &Db<MemVfs>,
    base: u64,
    pages: usize,
    entries_per_page: usize,
    freed_at: u64,
    tail: u64,
) -> LaidChain {
    let hosts: Vec<u64> = (0..pages as u64).map(|i| base + i).collect();
    let named: Vec<u64> = (0..(pages * entries_per_page) as u64)
        .map(|i| base + pages as u64 + i)
        .collect();
    for (index, &host) in hosts.iter().enumerate() {
        let next = hosts.get(index + 1).copied().unwrap_or(tail);
        let chunk: Vec<(u64, u64)> = named
            [index * entries_per_page..(index + 1) * entries_per_page]
            .iter()
            .map(|&page_id| (freed_at, page_id))
            .collect();
        write_chain(&db.pager, db.realm_id, db.page_size, &[host], &chunk, next)
            .await
            .unwrap();
    }
    LaidChain {
        head: hosts[0],
        hosts,
        named,
        next_free_id: base + (pages + pages * entries_per_page) as u64,
    }
}

async fn allocation_cursor(db: &Db<MemVfs>) -> u64 {
    db.writer.lock().await.next_page_id
}

/// Make a hand-laid chain the writer's durable free list.
async fn publish_chain(db: &Db<MemVfs>, head: u64, next_page_id: u64) {
    db.pager.flush_main(db.realm_id).await.unwrap();
    let mut state = db.writer.lock().await;
    state.free_list_root_page_id = head;
    state.next_page_id = next_page_id;
}

/// Every page id the chain rooted at `head` accounts for, split into the ids it
/// records as free and the ids it occupies itself.
async fn chain_census(db: &Db<MemVfs>, head: u64) -> (Vec<u64>, BTreeSet<u64>) {
    let (entries, chain_pages) = read_chain(&db.pager, db.realm_id, head).await.unwrap();
    (
        entries.into_iter().map(|(_, page_id)| page_id).collect(),
        chain_pages.into_iter().collect(),
    )
}

/// Page ids reachable from the committed data and catalog roots.
async fn live_page_ids(db: &Db<MemVfs>) -> BTreeSet<u64> {
    let (data_root, catalog_root, next_page_id) = {
        let state = db.writer.lock().await;
        (
            state.root_page_id,
            state.catalog_root_page_id,
            state.next_page_id,
        )
    };
    let mut live = BTreeSet::new();
    for root in [data_root, catalog_root] {
        if root == 0 {
            continue;
        }
        crate::btree::BTree::open(
            db.pager.clone(),
            db.realm_id,
            root,
            next_page_id,
            db.page_size,
        )
        .collect_all_page_ids(&mut live)
        .await
        .unwrap();
    }
    live
}

fn assert_no_duplicate_entries(entry_ids: &[u64], chain_pages: &BTreeSet<u64>) -> BTreeSet<u64> {
    let unique: BTreeSet<u64> = entry_ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        entry_ids.len(),
        "the free list records a page id twice — one page handed to two owners"
    );
    assert!(
        unique.is_disjoint(chain_pages),
        "a page is recorded free while hosting the chain"
    );
    unique
}

/// A rewrite that reaches only part of the chain must publish the rest through
/// the splice, not drop it: every page the retained tail accounted for is still
/// accounted for afterwards.
#[tokio::test(flavor = "current_thread")]
async fn a_windowed_rewrite_preserves_the_retained_tail() {
    let db =
        open_with(OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)).await;
    let base = allocation_cursor(&db).await;
    let laid = lay_chain(&db, base, WINDOW_PAGES + 8, 1, 0, 0).await;
    let accounted = laid.accounted();
    publish_chain(&db, laid.head, laid.next_free_id).await;

    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"live", b"value").await.unwrap();
        txn.commit().await.unwrap();
    }

    let head = db.writer.lock().await.free_list_root_page_id;
    let (entry_ids, chain_pages) = chain_census(&db, head).await;
    let unique = assert_no_duplicate_entries(&entry_ids, &chain_pages);

    // Nothing the pre-commit chain accounted for may go missing: an id is
    // either still free, now hosting the chain, or was handed to the allocator
    // and is live in the tree.
    let live = live_page_ids(&db).await;
    for page_id in &accounted {
        assert!(
            unique.contains(page_id) || chain_pages.contains(page_id) || live.contains(page_id),
            "page {page_id} was accounted for before the windowed rewrite and is now lost"
        );
    }
}

/// The window must sweep forward. New frees are prepended at the head, so a
/// splice point that parks at a fixed depth leaves every below-floor entry
/// deeper than it permanently unreachable — bounded memory paid for with an
/// unbounded disk leak. Empty commits isolate the sweep from allocator traffic:
/// nothing is freed and nothing is drawn from the cache, so the ids the chain
/// accounts for may only be rearranged, never legitimately removed.
#[tokio::test(flavor = "current_thread")]
async fn tail_compaction_sweeps_entries_stranded_beyond_the_window() {
    let db =
        open_with(OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)).await;
    let base = allocation_cursor(&db).await;
    let laid = lay_chain(&db, base, WINDOW_PAGES * 3 + 5, 1, 0, 0).await;
    let accounted = laid.accounted();
    publish_chain(&db, laid.head, laid.next_free_id).await;

    let opening = read_chain_prefix(&db.pager, db.realm_id, laid.head, WINDOW_PAGES)
        .await
        .unwrap();
    assert_ne!(
        opening.tail, 0,
        "the fixture must start with a chain longer than one window"
    );

    let mut swept = false;
    for _ in 0..16 {
        db.begin_write().await.unwrap().commit().await.unwrap();
        let head = db.writer.lock().await.free_list_root_page_id;

        let (entry_ids, chain_pages) = chain_census(&db, head).await;
        let unique = assert_no_duplicate_entries(&entry_ids, &chain_pages);
        for page_id in &accounted {
            assert!(
                unique.contains(page_id) || chain_pages.contains(page_id),
                "page {page_id} vanished while the window swept the tail"
            );
        }

        let window = read_chain_prefix(&db.pager, db.realm_id, head, WINDOW_PAGES)
            .await
            .unwrap();
        if window.tail == 0 {
            swept = true;
            break;
        }
    }
    assert!(
        swept,
        "the splice point never reached the end of the chain: entries deeper \
         than the scan window are stranded free forever"
    );
}

/// A page that leaves the chain into the allocator and comes back as a fresh
/// free must never end up recorded twice. The windowed rewrite only deletes
/// what it scanned, so this is the invariant that breaks first if the allocator
/// is ever fed an id from outside the window.
#[tokio::test(flavor = "current_thread")]
async fn recycling_across_many_commits_never_duplicates_a_page() {
    let db = open_with(OpenOptions::default().with_buffer_pool_pages(256)).await;
    for round in 0..40u32 {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0..12u32 {
            txn.put(format!("k{round:03}_{i:03}").as_bytes(), &[0u8; 300])
                .await
                .unwrap();
        }
        txn.commit().await.unwrap();

        let mut txn = db.begin_write().await.unwrap();
        for i in 0..12u32 {
            txn.delete(format!("k{round:03}_{i:03}").as_bytes())
                .await
                .unwrap();
        }
        txn.commit().await.unwrap();
    }

    let head = db.writer.lock().await.free_list_root_page_id;
    let (entry_ids, chain_pages) = chain_census(&db, head).await;
    let unique = assert_no_duplicate_entries(&entry_ids, &chain_pages);
    let live = live_page_ids(&db).await;
    let handed_out: Vec<u64> = unique.intersection(&live).copied().collect();
    assert!(
        handed_out.is_empty(),
        "pages are both live and recorded free: {handed_out:?}"
    );
}

/// The stall threshold is defined over the whole chain. A prefix walk cannot
/// produce that number, so the commit path streams the retained tail; drop that
/// and a backlog parked past the window stops being counted and the policy
/// silently stops firing.
#[tokio::test(flavor = "current_thread")]
async fn the_stall_policy_counts_a_backlog_parked_beyond_the_window() {
    let options = OpenOptions::default()
        .with_buffer_pool_pages(256)
        .with_commit_history_retain(RetainPolicy::Disabled)
        .with_reader_stall_threshold_pages(5);
    let db = open_with(options).await;
    db.set_reader_stall_policy(ReaderStallPolicy::Reject);
    {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"seed", b"v").await.unwrap();
        txn.commit().await.unwrap();
    }
    // A pinning reader is what makes the policy reachable at all, and its
    // commit id is the reclamation floor the backlog is measured against.
    let _pin = db.begin_read_non_abortable().await.unwrap();

    // The stuck backlog goes past the window; the window itself holds only
    // drainable entries, so a rewrite that counted the window alone would see
    // no backlog at all.
    let base = allocation_cursor(&db).await;
    let stuck = lay_chain(&db, base, 4, 10, u64::MAX, 0).await;
    let window = lay_chain(&db, stuck.next_free_id, WINDOW_PAGES, 1, 0, stuck.head).await;
    publish_chain(&db, window.head, window.next_free_id).await;

    let scanned = read_chain_prefix(&db.pager, db.realm_id, window.head, WINDOW_PAGES)
        .await
        .unwrap();
    assert_ne!(
        scanned.tail, 0,
        "the fixture must park the backlog beyond the scan window"
    );
    assert!(
        scanned.entries.iter().all(|(commit_id, _)| *commit_id == 0),
        "the fixture must leave no stuck entry inside the window"
    );

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"another", b"v").await.unwrap();
    let outcome = txn.commit().await;
    assert!(
        matches!(outcome, Err(PagedbError::DeferredFreeBacklog { .. })),
        "a backlog beyond the scan window must still trip the stall policy, got {outcome:?}"
    );
}
