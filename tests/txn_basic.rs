use bytes::Bytes;
use pagedb::vfs::memory::MemVfs;
use pagedb::{CommitId, Db, OpenOptions, PagedbError, ReaderStallPolicy, RealmId};

const PAGE: usize = 4096;

async fn open_db() -> Db<MemVfs> {
    open_db_on(MemVfs::new()).await
}

async fn open_db_on(vfs: MemVfs) -> Db<MemVfs> {
    Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn empty_db_begin_read_then_read_returns_none() {
    let db = open_db().await;
    let r = db.begin_read().await.unwrap();
    assert!(r.get(b"missing").await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn write_commit_then_read() {
    let db = open_db().await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        let cid = w.commit().await.unwrap();
        assert_eq!(cid, CommitId::new(1));
    }
    let r = db.begin_read().await.unwrap();
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn bulk_load_sorted_unique_commits_and_reads() {
    let db = open_db().await;
    let records = (0..10_000).map(|i| {
        Ok((
            format!("k-{i:05}").into_bytes(),
            Bytes::from(format!("v-{i:05}")),
        ))
    });
    let writer = db.begin_write().await.unwrap();
    let writer = writer.bulk_load_sorted_unique(records).await.unwrap();
    writer.commit().await.unwrap();

    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"k-09999").await.unwrap().as_deref(),
        Some(b"v-09999".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn bulk_load_multi_level_inline_and_overflow_records_survive_reopen() {
    let vfs = MemVfs::new();
    let db = open_db_on(vfs.clone()).await;
    let inline = Bytes::from(vec![0x2Bu8; 900]);
    let overflow = Bytes::from(vec![0xB4u8; PAGE]);
    // 5,000 sub-threshold records span enough leaves to require two internal levels.
    let records = (0..5_000).map(|i| {
        let value = if i % 17 == 0 {
            overflow.clone()
        } else {
            inline.clone()
        };
        Ok((format!("k-{i:05}").into_bytes(), value))
    });
    let writer = db.begin_write().await.unwrap();
    writer
        .bulk_load_sorted_unique(records)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    drop(db);

    let reopened = open_db_on(vfs).await;
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"k-00000").await.unwrap().as_deref(),
        Some(overflow.as_ref())
    );
    assert_eq!(
        reader.get(b"k-00001").await.unwrap().as_deref(),
        Some(inline.as_ref())
    );
    assert_eq!(
        reader.get(b"k-04999").await.unwrap().as_deref(),
        Some(inline.as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn bulk_load_keeps_an_oversized_byte_batch_record_intact() {
    let db = open_db().await;
    let huge = Bytes::from(vec![0xD3u8; 32 * 1024 * 1024 + 1]);
    let records = vec![
        Ok((b"a".to_vec(), huge.clone())),
        Ok((b"b".to_vec(), Bytes::from_static(b"tail"))),
    ];
    let writer = db.begin_write().await.unwrap();
    writer
        .bulk_load_sorted_unique(records)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();

    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"a").await.unwrap().as_deref(),
        Some(huge.as_ref())
    );
    assert_eq!(
        reader.get(b"b").await.unwrap().as_deref(),
        Some(b"tail".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn bulk_load_stream_error_aborts_the_consumed_transaction() {
    let db = open_db().await;
    let records = (0..10_000)
        .map(|i| Ok((format!("k-{i:05}").into_bytes(), Bytes::from_static(b"v"))))
        .chain(std::iter::once(Err(PagedbError::Io(
            std::io::Error::other("injected stream failure"),
        ))));
    let writer = db.begin_write().await.unwrap();
    let error = match writer.bulk_load_sorted_unique(records).await {
        Ok(_) => panic!("stream failure must abort the bulk transaction"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("injected stream failure"));

    let reader = db.begin_read().await.unwrap();
    assert!(reader.get(b"k-00000").await.unwrap().is_none());
    drop(reader);

    let mut writer = db.begin_write().await.unwrap();
    writer.put(b"after", b"ok").await.unwrap();
    writer.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn abort_discards_changes() {
    let db = open_db().await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.abort().await;
    }
    let r = db.begin_read().await.unwrap();
    assert!(r.get(b"k").await.unwrap().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_isolation_pin_survives_concurrent_writer() {
    let db = open_db().await;
    // commit 1: k=v1
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v1").await.unwrap();
        w.commit().await.unwrap();
    }
    // open a reader at commit 1
    let r = db.begin_read().await.unwrap();
    assert_eq!(r.commit_id(), CommitId::new(1));
    // commit 2: k=v2
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v2").await.unwrap();
        w.commit().await.unwrap();
    }
    // The pre-existing reader's view depends on the snapshot pin —
    // because the BTree CoW path leaves the old root in place (just
    // unreferenced from the new header), the reader at commit_id=1
    // continues to see "v1" by descending from its pinned root.
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v1".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn latest_commit_advances_on_commit() {
    let db = open_db().await;
    assert_eq!(db.latest_commit(), CommitId::new(0));
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"a", b"1").await.unwrap();
        w.commit().await.unwrap();
    }
    let reader = db.begin_read_non_abortable().await.unwrap();
    assert_eq!(reader.commit_id(), CommitId::new(1));
    assert_eq!(
        reader.get(b"a").await.unwrap().as_deref(),
        Some(b"1".as_ref())
    );
    drop(reader);
    assert_eq!(db.latest_commit(), CommitId::new(1));
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"b", b"2").await.unwrap();
        w.commit().await.unwrap();
    }
    assert_eq!(db.latest_commit(), CommitId::new(2));
}

#[tokio::test(flavor = "current_thread")]
async fn begin_read_at_current_succeeds() {
    let db = open_db().await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.commit().await.unwrap();
    }
    let r = db.begin_read_at(CommitId::new(1)).await.unwrap();
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn begin_read_at_past_returns_commit_gone() {
    // With Count(2), writing 3 commits prunes commit 1; begin_read_at(1) must
    // return CommitGone.
    use pagedb::options::RetainPolicy;
    use pagedb::vfs::memory::MemVfs;
    let opts = OpenOptions::default().with_commit_history_retain(RetainPolicy::Count(2));
    let db = Db::open(MemVfs::new(), [9u8; 32], PAGE, RealmId::new([1; 16]), opts)
        .await
        .unwrap();
    for _ in 0..3u32 {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k", b"v").await.unwrap();
        w.commit().await.unwrap();
    }
    let result = db.begin_read_at(CommitId::new(1)).await;
    match result {
        Err(PagedbError::CommitGone { .. }) => {}
        Err(e) => panic!("expected CommitGone, got error {e:?}"),
        Ok(_) => panic!("expected CommitGone but got Ok"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn begin_read_at_future_returns_commit_gone() {
    let db = open_db().await;
    let err = db.begin_read_at(CommitId::new(99)).await.err().unwrap();
    assert!(matches!(err, PagedbError::CommitGone { .. }));
}

#[tokio::test(flavor = "current_thread")]
async fn write_txn_serializes() {
    use std::sync::Arc;
    use tokio::task::LocalSet;

    let local = LocalSet::new();
    local
        .run_until(async {
            let db = Arc::new(open_db().await);
            let db2 = db.clone();
            // First writer holds the slot; second writer must wait.
            let mut w1 = db.begin_write().await.unwrap();
            w1.put(b"k", b"v").await.unwrap();
            // Spawn a second begin_write using spawn_local.
            let handle = tokio::task::spawn_local(async move {
                let mut w2 = db2.begin_write().await.unwrap();
                w2.put(b"k2", b"v2").await.unwrap();
                w2.commit().await.unwrap()
            });
            // Yield a few times to let the spawned task try (and block) on the lock.
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
            assert!(!handle.is_finished(), "second writer should be blocked");
            w1.commit().await.unwrap();
            let cid2 = handle.await.unwrap();
            assert_eq!(cid2, CommitId::new(2));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn reader_registration_drops_clean() {
    let db = open_db().await;
    {
        let _r1 = db.begin_read().await.unwrap();
        let _r2 = db.begin_read().await.unwrap();
        let _r3 = db.begin_read().await.unwrap();
        // 3 readers registered
    }
    // After scope, all unregistered; opening a writer should not contend.
    let mut w = db.begin_write().await.unwrap();
    w.put(b"a", b"b").await.unwrap();
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn reader_stall_policy_settable() {
    let db = open_db().await;
    assert_eq!(db.reader_stall_policy(), ReaderStallPolicy::AbortOldest);
    db.set_reader_stall_policy(ReaderStallPolicy::Reject);
    assert_eq!(db.reader_stall_policy(), ReaderStallPolicy::Reject);
    db.set_reader_stall_policy(ReaderStallPolicy::Unbounded);
    assert_eq!(db.reader_stall_policy(), ReaderStallPolicy::Unbounded);
}

/// Rows for the bounded-scan tests: `row:0000`..`row:0049`, all one realm.
async fn open_db_with_rows(count: usize) -> Db<MemVfs> {
    let db = open_db().await;
    let mut w = db.begin_write().await.unwrap();
    for i in 0..count {
        w.put(format!("row:{i:04}").as_bytes(), b"v").await.unwrap();
    }
    w.commit().await.unwrap();
    db
}

#[tokio::test(flavor = "current_thread")]
async fn scan_from_stops_at_limit() {
    let db = open_db_with_rows(50).await;
    let r = db.begin_read().await.unwrap();
    let rows = r.scan_from(b"row:0000", 10).await.unwrap();
    assert_eq!(rows.len(), 10);
    assert_eq!(rows[0].0.as_ref(), b"row:0000");
    assert_eq!(rows[9].0.as_ref(), b"row:0009");
}

#[tokio::test(flavor = "current_thread")]
async fn scan_from_starts_at_or_after_key() {
    let db = open_db_with_rows(50).await;
    let r = db.begin_read().await.unwrap();
    // Start key need not exist: the scan lands on the first row at or after it.
    let rows = r.scan_from(b"row:0020", 3).await.unwrap();
    assert_eq!(rows[0].0.as_ref(), b"row:0020");
    let rows = r.scan_from(b"row:0019z", 1).await.unwrap();
    assert_eq!(rows[0].0.as_ref(), b"row:0020");
}

#[tokio::test(flavor = "current_thread")]
async fn scan_from_short_batch_means_end_of_tree() {
    let db = open_db_with_rows(50).await;
    let r = db.begin_read().await.unwrap();
    let rows = r.scan_from(b"row:0045", 10).await.unwrap();
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[4].0.as_ref(), b"row:0049");
    assert!(r.scan_from(b"zzz", 10).await.unwrap().is_empty());
    assert!(r.scan_from(b"row:0000", 0).await.unwrap().is_empty());
}

/// The documented resume protocol — append `0x00` to the last key returned —
/// must page the whole tree exactly once, skipping and repeating nothing.
#[tokio::test(flavor = "current_thread")]
async fn scan_from_resume_protocol_pages_every_row_once() {
    let db = open_db_with_rows(50).await;
    let r = db.begin_read().await.unwrap();
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut cursor: Vec<u8> = Vec::new();
    loop {
        let batch = r.scan_from(&cursor, 7).await.unwrap();
        if batch.is_empty() {
            break;
        }
        cursor = batch.last().unwrap().0.to_vec();
        cursor.push(0x00);
        seen.extend(batch.into_iter().map(|(k, _)| k.to_vec()));
    }
    assert_eq!(seen.len(), 50);
    let mut expected: Vec<Vec<u8>> = (0..50)
        .map(|i| format!("row:{i:04}").into_bytes())
        .collect();
    expected.sort();
    assert_eq!(seen, expected);
}

#[tokio::test(flavor = "current_thread")]
async fn scan_from_agrees_with_materialising_scan() {
    let db = open_db_with_rows(50).await;
    let r = db.begin_read().await.unwrap();
    let bounded = r.scan_from(b"row:0010", 8).await.unwrap();
    let eager = r.scan(b"row:0010", b"row:0018").await.unwrap();
    assert_eq!(bounded, eager);
}

#[tokio::test(flavor = "current_thread")]
async fn scan_prefix_from_stops_at_prefix_boundary() {
    let db = open_db().await;
    {
        let mut w = db.begin_write().await.unwrap();
        for i in 0..5 {
            w.put(format!("a:{i}").as_bytes(), b"v").await.unwrap();
            w.put(format!("b:{i}").as_bytes(), b"v").await.unwrap();
        }
        w.commit().await.unwrap();
    }
    let r = db.begin_read().await.unwrap();
    // Limit is generous; the prefix boundary is what ends the range.
    let rows = r.scan_prefix_from(b"a:", b"a:", 100).await.unwrap();
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|(k, _)| k.starts_with(b"a:")));
}

/// A scan on a write transaction must observe that transaction's own
/// uncommitted writes. This is what lets read-modify-write over a range be one
/// transaction; if scans read through to the published snapshot instead, every
/// such pattern silently operates on stale data.
#[tokio::test(flavor = "current_thread")]
async fn write_txn_scans_observe_uncommitted_writes() {
    let db = open_db().await;
    let mut w = db.begin_write().await.unwrap();
    for i in 0..2_000u32 {
        w.put(format!("k{i:05}").as_bytes(), b"v1").await.unwrap();
    }
    w.commit().await.unwrap();

    // Opened before the writer: a reader cannot *begin* while a write txn is
    // live, because `WriteTxn` holds the visibility gate for its whole life.
    let r = db.begin_read().await.unwrap();

    let mut w = db.begin_write().await.unwrap();
    w.put(b"k00500", b"v2").await.unwrap();
    w.delete(b"k00501").await.unwrap();
    w.put(b"k99999", b"new").await.unwrap();

    let rows = w.scan(b"k00499", b"k00502").await.unwrap();
    let seen: Vec<(&[u8], &[u8])> = rows.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect();
    assert_eq!(
        seen,
        vec![
            (b"k00499".as_ref(), b"v1".as_ref()),
            (b"k00500".as_ref(), b"v2".as_ref()),
        ],
        "scan must see the overwrite and the delete"
    );

    // The newest key is uncommitted; reverse paging must still find it.
    let newest = w.scan_rev_from(None, 1).await.unwrap();
    assert_eq!(newest[0].0.as_ref(), b"k99999");
    assert_eq!(
        w.last_key().await.unwrap().as_deref(),
        Some(b"k99999".as_ref())
    );

    let prefixed = w.scan_prefix_from(b"k005", b"k005", 3).await.unwrap();
    assert_eq!(prefixed.len(), 3);
    assert_eq!(prefixed[0].1.as_ref(), b"v2");

    // The pre-existing reader is pinned to the published snapshot and must see
    // none of it.
    assert_eq!(
        r.get(b"k00500").await.unwrap().as_deref(),
        Some(b"v1".as_ref())
    );
    assert!(r.get(b"k99999").await.unwrap().is_none());
    drop(r);

    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"k00500").await.unwrap().as_deref(),
        Some(b"v2".as_ref())
    );
    assert!(r.get(b"k00501").await.unwrap().is_none());
    assert_eq!(
        r.scan_rev_from(None, 1).await.unwrap()[0].0.as_ref(),
        b"k99999"
    );
}

/// Reading a window of a large value must not depend on materialising it.
#[tokio::test(flavor = "current_thread")]
async fn get_range_reads_a_window_of_a_large_value() {
    let db = open_db().await;
    let blob: Vec<u8> = (0..(PAGE * 20) as u32).map(|i| (i % 253) as u8).collect();
    let mut w = db.begin_write().await.unwrap();
    w.put(b"blob", &blob).await.unwrap();
    w.commit().await.unwrap();

    let r = db.begin_read().await.unwrap();
    let window = r.get_range(b"blob", 40_000, 1_000).await.unwrap().unwrap();
    assert_eq!(window.as_ref(), &blob[40_000..41_000]);
    let tail = r
        .get_range(b"blob", blob.len() as u64 - 5, 99)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tail.as_ref(), &blob[blob.len() - 5..]);
    assert_eq!(
        r.get(b"blob").await.unwrap().unwrap().as_ref(),
        blob.as_slice()
    );
}
