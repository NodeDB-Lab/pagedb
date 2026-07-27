//! Tests for the deep-walk integrity checker.

use pagedb::options::RetainPolicy;
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, PagedbError, RealmId, run_deep_walk};

const KEK: [u8; 32] = [3u8; 32];
const REALM: RealmId = RealmId::new([1u8; 16]);

async fn open_db() -> Db<MemVfs> {
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    Db::open(MemVfs::new(), KEK, 4096, REALM, opts)
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn clean_db_reports_clean() {
    let db = open_db().await;

    // Write some data.
    let mut txn = db.begin_write().await.unwrap();
    for i in 0u64..20 {
        let key = format!("key{i:04}");
        txn.put(key.as_bytes(), &[i as u8; 128]).await.unwrap();
    }
    txn.commit().await.unwrap();

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.page_issues.is_empty(),
        "expected no page issues, got: {:?}",
        report.page_issues
    );
    assert!(
        report.segment_issues.is_empty(),
        "expected no segment issues"
    );
    assert!(report.drift_issues.is_empty(), "expected no drift issues");
    assert!(
        report.pages_examined > 0,
        "should have examined at least some pages"
    );
    assert!(report.is_clean(), "report should be clean");
}

#[tokio::test(flavor = "current_thread")]
async fn empty_db_reports_clean() {
    let db = open_db().await;
    let report = run_deep_walk(&db).await.unwrap();
    // An empty db has no data pages (next_page_id == 4, pages 4..4 is empty).
    assert!(report.is_clean(), "empty db should be clean");
}

#[tokio::test(flavor = "current_thread")]
async fn corrupt_page_detected() {
    let vfs = MemVfs::new();
    let opts = OpenOptions::default().with_buffer_pool_pages(64);
    let db = Db::open(vfs.clone(), KEK, 4096, REALM, opts.clone())
        .await
        .unwrap();

    // Write data to create some pages.
    let mut txn = db.begin_write().await.unwrap();
    for i in 0u64..10 {
        let key = format!("ck{i:04}");
        txn.put(key.as_bytes(), &[0xABu8; 64]).await.unwrap();
    }
    txn.commit().await.unwrap();

    // Page 4 is the first data page (pages 0-3 are reserved), so the writes
    // above must have allocated it for the corruption below to land on a real
    // page rather than past the end of the file.
    let next_pid = db.stats().await.unwrap().main_db_next_page_id;
    assert!(
        next_pid > 4,
        "the seed writes must have allocated at least one data page; got {next_pid}"
    );
    // Close the store before touching its bytes underneath it, the way a
    // crash-then-fsck sequence does.
    drop(db);

    // Corrupt a data page by flipping bytes directly in the MemVfs.
    {
        use pagedb::vfs::OpenMode;
        use pagedb::vfs::{Vfs, VfsFile};
        let mut f = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
        // Flip bytes in the AEAD tag of page 4 (last 16 bytes of the page).
        let corrupt_offset = 4 * 4096 + 4096 - 16;
        let mut corrupt_buf = [0u8; 16];
        f.read_at(corrupt_offset, &mut corrupt_buf).await.unwrap();
        for b in &mut corrupt_buf {
            *b ^= 0xFF;
        }
        f.write_at(corrupt_offset, &corrupt_buf).await.unwrap();
        f.sync().await.unwrap();
    }

    // A fresh handle starts with a cold buffer pool, so the deep walk reads the
    // corrupted bytes from disk instead of the page the writer left warm.
    let db = Db::open(vfs.clone(), KEK, 4096, REALM, opts).await.unwrap();
    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        !report.page_issues.is_empty(),
        "should detect corrupted page"
    );
    assert!(
        report.page_issues.iter().any(|i| i.page_id == 4),
        "page 4 should be reported as corrupted; issues: {:?}",
        report.page_issues
    );
}

#[tokio::test(flavor = "current_thread")]
async fn free_list_pages_are_accounted_not_orphans() {
    // Disable history so deleted pages enter the durable free-list immediately
    // (no retained snapshot pins them).
    let opts = OpenOptions::default()
        .with_buffer_pool_pages(64)
        .with_commit_history_retain(pagedb::options::RetainPolicy::Disabled);
    let db = Db::open(MemVfs::new(), KEK, 4096, REALM, opts)
        .await
        .unwrap();

    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..300 {
            w.put(format!("k{i:05}").as_bytes(), &[7u8; 128])
                .await
                .unwrap();
        }
        w.commit().await.unwrap();
    }
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0u32..250 {
            w.delete(format!("k{i:05}").as_bytes()).await.unwrap();
        }
        w.commit().await.unwrap();
    }
    assert!(
        db.stats().await.unwrap().free_list_pending_entries > 0,
        "setup should have populated the durable free-list"
    );

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.page_issues.is_empty(),
        "free-listed/chain pages must verify cleanly, got: {:?}",
        report.page_issues
    );
    // The free-list chain pages and the pages they track are accounted for, so
    // none should be reported as orphans.
    assert!(
        report.orphan_page_ids.is_empty(),
        "free-list pages must not be reported as orphans, got: {:?}",
        report.orphan_page_ids
    );
    assert!(report.is_clean(), "report should be clean");
}

/// With commit-history retention enabled, superseded-but-retained tree
/// versions are still reachable through the commit-history index used by
/// `begin_read_at`. A healthy store with several retained generations must
/// not report those pages as orphans, and a retained generation must still
/// be genuinely readable back.
#[tokio::test(flavor = "current_thread")]
async fn retained_history_pages_are_not_reported_as_orphans() {
    let opts = OpenOptions::default()
        .with_buffer_pool_pages(64)
        .with_commit_history_retain(RetainPolicy::Count(1024));
    let db = Db::open(MemVfs::new(), KEK, 4096, REALM, opts)
        .await
        .unwrap();

    // Repeatedly overwrite the same key set across several generations so
    // copy-on-write genuinely supersedes earlier pages instead of only
    // appending new ones. Enough keys/bytes to span multiple B+ tree pages.
    let mut commits = Vec::new();
    for generation in 0u8..24 {
        let mut txn = db.begin_write().await.unwrap();
        for i in 0u32..300 {
            let key = format!("hkey{i:05}");
            txn.put(key.as_bytes(), &[generation; 128]).await.unwrap();
        }
        let commit_id = txn.commit().await.unwrap();
        commits.push(commit_id);
    }

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.orphan_page_ids.is_empty(),
        "pages held for retained history are accounted by the deferred-free \
         chain, not leaked, got {} orphans: {:?}",
        report.orphan_page_ids.len(),
        report.orphan_page_ids
    );

    // The pages the walk just declined to call orphans are genuinely live: an
    // earlier retained commit still opens and reads back its own generation.
    let earliest = commits[0];
    let historical = db.begin_read_at(earliest).await.unwrap();
    assert_eq!(
        historical.get(b"hkey00000").await.unwrap().as_deref(),
        Some([0u8; 128].as_slice()),
        "retained historical commit must still read back its own generation's value"
    );
    drop(historical);

    // Compaction is the pass that actually reclaims superseded pages. It
    // retires retained history rather than preserving it, so the reachable set
    // shrinks to the live roots — and must still balance exactly.
    db.compact_now().await.unwrap();
    assert!(
        matches!(
            db.begin_read_at(earliest).await,
            Err(PagedbError::CommitGone { .. })
        ),
        "compaction retires retained history instead of pinning it forever"
    );

    let report = run_deep_walk(&db).await.unwrap();
    assert!(
        report.orphan_page_ids.is_empty(),
        "compaction must return every superseded page to the free list, got {} \
         orphans: {:?}",
        report.orphan_page_ids.len(),
        report.orphan_page_ids
    );
}
