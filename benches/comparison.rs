//! Cross-engine comparison benchmark — pagedb vs redb vs rocksdb vs sqlite.
//!
//! Each (engine, phase) pair is one fluxbench `#[bench]`. `#[compare]` blocks
//! group the four engines side-by-side per phase and produce a speedup table.
//!
//! Workload modelled after redb's `lmdb_benchmark.rs` (24-byte random keys,
//! 150-byte random values, RNG seed 3) so the relative numbers map onto the
//! published redb table. Scaled down to keep bench iteration fast:
//!   - bulk-load and removals: full-pipeline benches with `samples = 3`
//!   - individual writes / batch writes: per-txn latency, many samples
//!   - random reads / range reads: per-op latency on a preloaded DB
//!
//! Run with: `cargo bench --bench comparison`

#![allow(dead_code)] // verify/synthetic/compare placeholder structs

use std::cell::RefCell;
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::Arc;

use fluxbench::prelude::*;
use fluxbench::{bench, compare};
use rocksdb::{IteratorMode, OptimisticTransactionDB, SingleThreaded};
use rusqlite::Connection;
use tokio::sync::Mutex as AsyncMutex;

use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::vfs::{DefaultVfs as BenchVfs, open_default};
use pagedb::{Db, RealmId};

// --- workload parameters (scaled-down redb defaults) ------------------------

const PRELOAD: usize = 100_000;
const BATCH_SIZE: usize = 1_000;
const KEY_SIZE: usize = 24;
const VALUE_SIZE: usize = 150;
const RNG_SEED: u64 = 3;
const SCAN_LEN: usize = 10;

// --- shared RNG helpers -----------------------------------------------------

fn random_pair(rng: &mut fastrand::Rng) -> ([u8; KEY_SIZE], Vec<u8>) {
    let mut key = [0u8; KEY_SIZE];
    rng.fill(&mut key);
    let mut value = vec![0u8; VALUE_SIZE];
    rng.fill(&mut value);
    (key, value)
}

fn make_rng() -> fastrand::Rng {
    fastrand::Rng::with_seed(RNG_SEED)
}

fn preloaded_keys() -> Vec<[u8; KEY_SIZE]> {
    let mut rng = make_rng();
    (0..PRELOAD).map(|_| random_pair(&mut rng).0).collect()
}

// --- tokio runtime singleton ------------------------------------------------

thread_local! {
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
}

fn with_rt<R>(f: impl FnOnce(&tokio::runtime::Runtime) -> R) -> R {
    RT.with(|rt| f(rt))
}

// --- pagedb harness ---------------------------------------------------------

struct PagedbBench {
    db: Arc<AsyncMutex<Db<BenchVfs>>>,
    _dir: tempfile::TempDir,
}

fn open_pagedb_fresh() -> PagedbBench {
    let dir = tempfile::TempDir::new().unwrap();
    let vfs = open_default(dir.path()).expect("open default vfs");
    let opts = OpenOptions::default()
        // Fair-comparison: redb has no equivalent commit-history index;
        // disable pagedb's so the bench measures the same feature surface.
        // (`Disabled` is a pagedb extension; not in the architecture spec.)
        .with_commit_history_retain(RetainPolicy::Disabled)
        // Fair-comparison: redb does not persist a deferred-free queue per
        // commit. Opt into pagedb's fast-free path so write-latency numbers
        // measure the same per-commit work. Production embedders that turn
        // this on must compact periodically.
        .with_skip_freelist_persistence_when_no_readers(true)
        .with_metrics_enabled(false)
        // Large bulk loads need a generous nonce budget per txn.
        .with_anchor_budget(10_000_000);
    let db = with_rt(|rt| {
        rt.block_on(async {
            Db::open_internal_with_options(vfs, [0xAB; 32], 4096, RealmId::new([1; 16]), opts)
                .await
                .unwrap()
        })
    });
    PagedbBench {
        db: Arc::new(AsyncMutex::new(db)),
        _dir: dir,
    }
}

fn preload_pagedb(b: &PagedbBench) {
    let mut rng = make_rng();
    let db = b.db.clone();
    with_rt(|rt| {
        rt.block_on(async {
            let g = db.lock().await;
            let mut w = g.begin_write().await.unwrap();
            for _ in 0..PRELOAD {
                let (k, v) = random_pair(&mut rng);
                w.put(&k, &v).await.unwrap();
            }
            w.commit().await.unwrap();
        })
    });
}

thread_local! {
    static PAGEDB_PRELOADED: RefCell<Option<Arc<PagedbBench>>> = const { RefCell::new(None) };
}

fn pagedb_preloaded() -> Arc<PagedbBench> {
    PAGEDB_PRELOADED.with(|cell| {
        if cell.borrow().is_none() {
            let b = open_pagedb_fresh();
            preload_pagedb(&b);
            *cell.borrow_mut() = Some(Arc::new(b));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

// --- redb harness -----------------------------------------------------------

struct RedbBench {
    db: Arc<redb::Database>,
    _dir: tempfile::TempDir,
}

const REDB_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("kv");

fn open_redb_fresh() -> RedbBench {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bench.redb");
    let db = redb::Database::create(&path).unwrap();
    RedbBench {
        db: Arc::new(db),
        _dir: dir,
    }
}

fn preload_redb(b: &RedbBench) {
    let mut rng = make_rng();
    let wx = b.db.begin_write().unwrap();
    {
        let mut t = wx.open_table(REDB_TABLE).unwrap();
        for _ in 0..PRELOAD {
            let (k, v) = random_pair(&mut rng);
            t.insert(k.as_slice(), v.as_slice()).unwrap();
        }
    }
    wx.commit().unwrap();
}

thread_local! {
    static REDB_PRELOADED: RefCell<Option<Arc<RedbBench>>> = const { RefCell::new(None) };
}

fn redb_preloaded() -> Arc<RedbBench> {
    REDB_PRELOADED.with(|cell| {
        if cell.borrow().is_none() {
            let b = open_redb_fresh();
            preload_redb(&b);
            *cell.borrow_mut() = Some(Arc::new(b));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

// --- rocksdb harness --------------------------------------------------------

struct RocksdbBench {
    db: Arc<OptimisticTransactionDB<SingleThreaded>>,
    _dir: tempfile::TempDir,
}

fn open_rocksdb_fresh() -> RocksdbBench {
    let dir = tempfile::TempDir::new().unwrap();
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    let db: OptimisticTransactionDB<SingleThreaded> =
        OptimisticTransactionDB::open(&opts, dir.path()).unwrap();
    RocksdbBench {
        db: Arc::new(db),
        _dir: dir,
    }
}

fn preload_rocksdb(b: &RocksdbBench) {
    let mut rng = make_rng();
    let txn = b.db.transaction();
    for _ in 0..PRELOAD {
        let (k, v) = random_pair(&mut rng);
        txn.put(k, v).unwrap();
    }
    txn.commit().unwrap();
}

thread_local! {
    static ROCKSDB_PRELOADED: RefCell<Option<Arc<RocksdbBench>>> = const { RefCell::new(None) };
}

fn rocksdb_preloaded() -> Arc<RocksdbBench> {
    ROCKSDB_PRELOADED.with(|cell| {
        if cell.borrow().is_none() {
            let b = open_rocksdb_fresh();
            preload_rocksdb(&b);
            *cell.borrow_mut() = Some(Arc::new(b));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

// --- sqlite harness ---------------------------------------------------------

struct SqliteBench {
    path: PathBuf,
    _dir: tempfile::TempDir,
}

fn open_sqlite_fresh() -> SqliteBench {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bench.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB)",
        [],
    )
    .unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    drop(conn);
    SqliteBench { path, _dir: dir }
}

fn sqlite_conn(b: &SqliteBench) -> Connection {
    let conn = Connection::open(&b.path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn
}

fn preload_sqlite(b: &SqliteBench) {
    let conn = sqlite_conn(b);
    let mut rng = make_rng();
    let txn = conn.unchecked_transaction().unwrap();
    {
        let mut stmt = txn
            .prepare("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)")
            .unwrap();
        for _ in 0..PRELOAD {
            let (k, v) = random_pair(&mut rng);
            stmt.execute(rusqlite::params![&k[..], &v[..]]).unwrap();
        }
    }
    txn.commit().unwrap();
}

thread_local! {
    static SQLITE_PRELOADED: RefCell<Option<Arc<SqliteBench>>> = const { RefCell::new(None) };
}

fn sqlite_preloaded() -> Arc<SqliteBench> {
    SQLITE_PRELOADED.with(|cell| {
        if cell.borrow().is_none() {
            let b = open_sqlite_fresh();
            preload_sqlite(&b);
            *cell.borrow_mut() = Some(Arc::new(b));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

// ============================================================================
// bulk_load: load PRELOAD items in one txn. iter_with_setup → fresh DB per iter.
// ============================================================================

#[bench(group = "compare/bulk_load", samples = 3)]
fn bulk_load_pagedb(b: &mut Bencher) {
    b.iter_with_setup(open_pagedb_fresh, |db| {
        let mut rng = make_rng();
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.db.lock().await;
                let mut w = g.begin_write().await.unwrap();
                for _ in 0..PRELOAD {
                    let (k, v) = random_pair(&mut rng);
                    w.put(&k, &v).await.unwrap();
                }
                w.commit().await.unwrap();
            })
        })
    });
}

#[bench(group = "compare/bulk_load", samples = 3)]
fn bulk_load_redb(b: &mut Bencher) {
    b.iter_with_setup(open_redb_fresh, |bench| {
        let mut rng = make_rng();
        let wx = bench.db.begin_write().unwrap();
        {
            let mut t = wx.open_table(REDB_TABLE).unwrap();
            for _ in 0..PRELOAD {
                let (k, v) = random_pair(&mut rng);
                t.insert(k.as_slice(), v.as_slice()).unwrap();
            }
        }
        wx.commit().unwrap();
    });
}

#[bench(group = "compare/bulk_load", samples = 3)]
fn bulk_load_rocksdb(b: &mut Bencher) {
    b.iter_with_setup(open_rocksdb_fresh, |bench| {
        let mut rng = make_rng();
        let txn = bench.db.transaction();
        for _ in 0..PRELOAD {
            let (k, v) = random_pair(&mut rng);
            txn.put(k, v).unwrap();
        }
        txn.commit().unwrap();
    });
}

#[bench(group = "compare/bulk_load", samples = 3)]
fn bulk_load_sqlite(b: &mut Bencher) {
    b.iter_with_setup(open_sqlite_fresh, |bench| {
        let conn = sqlite_conn(&bench);
        let mut rng = make_rng();
        let txn = conn.unchecked_transaction().unwrap();
        {
            let mut stmt = txn
                .prepare("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)")
                .unwrap();
            for _ in 0..PRELOAD {
                let (k, v) = random_pair(&mut rng);
                stmt.execute(rusqlite::params![&k[..], &v[..]]).unwrap();
            }
        }
        txn.commit().unwrap();
    });
}

#[compare(
    id = "cmp_bulk_load",
    title = "Bulk load (PRELOAD items / 1 txn)",
    benchmarks = [
        "bulk_load_pagedb",
        "bulk_load_redb",
        "bulk_load_rocksdb",
        "bulk_load_sqlite"
    ],
    baseline = "bulk_load_redb",
    metric = "mean"
)]
struct CmpBulkLoad;

// ============================================================================
// sorted_bulk_load: PRELOAD monotonically-increasing keys in 1 txn. Each engine
// uses its best API for sorted input. For pagedb this is the new
// `WriteTxn::put_append` fast path (skips descent via cached rightmost path).
// ============================================================================

fn sorted_key(i: usize) -> [u8; KEY_SIZE] {
    // Big-endian counter padded out to KEY_SIZE bytes so byte-comparison
    // matches numeric order.
    let mut k = [0u8; KEY_SIZE];
    k[..8].copy_from_slice(&(i as u64).to_be_bytes());
    k
}

fn sorted_value(rng: &mut fastrand::Rng) -> Vec<u8> {
    let mut v = vec![0u8; VALUE_SIZE];
    rng.fill(&mut v);
    v
}

#[bench(group = "compare/sorted_bulk_load", samples = 3)]
fn sorted_bulk_load_pagedb(b: &mut Bencher) {
    b.iter_with_setup(open_pagedb_fresh, |db| {
        let mut rng = make_rng();
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.db.lock().await;
                let mut w = g.begin_write().await.unwrap();
                for i in 0..PRELOAD {
                    let k = sorted_key(i);
                    let v = sorted_value(&mut rng);
                    w.put_append(&k, &v).await.unwrap();
                }
                w.commit().await.unwrap();
            })
        })
    });
}

#[bench(group = "compare/sorted_bulk_load", samples = 3)]
fn sorted_bulk_load_redb(b: &mut Bencher) {
    b.iter_with_setup(open_redb_fresh, |bench| {
        let mut rng = make_rng();
        let wx = bench.db.begin_write().unwrap();
        {
            let mut t = wx.open_table(REDB_TABLE).unwrap();
            for i in 0..PRELOAD {
                let k = sorted_key(i);
                let v = sorted_value(&mut rng);
                t.insert(k.as_slice(), v.as_slice()).unwrap();
            }
        }
        wx.commit().unwrap();
    });
}

#[bench(group = "compare/sorted_bulk_load", samples = 3)]
fn sorted_bulk_load_rocksdb(b: &mut Bencher) {
    b.iter_with_setup(open_rocksdb_fresh, |bench| {
        let mut rng = make_rng();
        let txn = bench.db.transaction();
        for i in 0..PRELOAD {
            let k = sorted_key(i);
            let v = sorted_value(&mut rng);
            txn.put(k, v).unwrap();
        }
        txn.commit().unwrap();
    });
}

#[bench(group = "compare/sorted_bulk_load", samples = 3)]
fn sorted_bulk_load_sqlite(b: &mut Bencher) {
    b.iter_with_setup(open_sqlite_fresh, |bench| {
        let conn = sqlite_conn(&bench);
        let mut rng = make_rng();
        let txn = conn.unchecked_transaction().unwrap();
        {
            let mut stmt = txn
                .prepare("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)")
                .unwrap();
            for i in 0..PRELOAD {
                let k = sorted_key(i);
                let v = sorted_value(&mut rng);
                stmt.execute(rusqlite::params![&k[..], &v[..]]).unwrap();
            }
        }
        txn.commit().unwrap();
    });
}

#[compare(
    id = "cmp_sorted_bulk_load",
    title = "Sorted bulk load (PRELOAD monotonic-key items / 1 txn)",
    benchmarks = [
        "sorted_bulk_load_pagedb",
        "sorted_bulk_load_redb",
        "sorted_bulk_load_rocksdb",
        "sorted_bulk_load_sqlite"
    ],
    baseline = "sorted_bulk_load_redb",
    metric = "mean"
)]
struct CmpSortedBulkLoad;

// ============================================================================
// individual_write: 1 key per committed txn — fsync-dominated. Many samples.
// ============================================================================

#[bench(group = "compare/individual_write")]
fn individual_write_pagedb(b: &mut Bencher) {
    let bench = pagedb_preloaded();
    let mut rng = make_rng();
    // Skip the preloaded keyspace so we measure pure insert (not update).
    for _ in 0..PRELOAD {
        let _ = random_pair(&mut rng);
    }
    b.iter(|| {
        let (k, v) = random_pair(&mut rng);
        with_rt(|rt| {
            rt.block_on(async {
                let g = bench.db.lock().await;
                let mut w = g.begin_write().await.unwrap();
                w.put(&k, &v).await.unwrap();
                w.commit().await.unwrap();
            })
        })
    });
}

#[bench(group = "compare/individual_write")]
fn individual_write_redb(b: &mut Bencher) {
    let bench = redb_preloaded();
    let mut rng = make_rng();
    for _ in 0..PRELOAD {
        let _ = random_pair(&mut rng);
    }
    b.iter(|| {
        let (k, v) = random_pair(&mut rng);
        let wx = bench.db.begin_write().unwrap();
        {
            let mut t = wx.open_table(REDB_TABLE).unwrap();
            t.insert(k.as_slice(), v.as_slice()).unwrap();
        }
        wx.commit().unwrap();
    });
}

#[bench(group = "compare/individual_write")]
fn individual_write_rocksdb(b: &mut Bencher) {
    let bench = rocksdb_preloaded();
    let mut rng = make_rng();
    for _ in 0..PRELOAD {
        let _ = random_pair(&mut rng);
    }
    b.iter(|| {
        let (k, v) = random_pair(&mut rng);
        let txn = bench.db.transaction();
        txn.put(k, v).unwrap();
        txn.commit().unwrap();
    });
}

#[bench(group = "compare/individual_write")]
fn individual_write_sqlite(b: &mut Bencher) {
    let bench = sqlite_preloaded();
    let conn = sqlite_conn(&bench);
    let mut rng = make_rng();
    for _ in 0..PRELOAD {
        let _ = random_pair(&mut rng);
    }
    b.iter(|| {
        let (k, v) = random_pair(&mut rng);
        let txn = conn.unchecked_transaction().unwrap();
        txn.execute(
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
            rusqlite::params![&k[..], &v[..]],
        )
        .unwrap();
        txn.commit().unwrap();
    });
}

#[compare(
    id = "cmp_individual_write",
    title = "Individual write (1 key / txn — fsync-bound)",
    benchmarks = [
        "individual_write_pagedb",
        "individual_write_redb",
        "individual_write_rocksdb",
        "individual_write_sqlite"
    ],
    baseline = "individual_write_redb",
    metric = "mean"
)]
struct CmpIndividualWrite;

// ============================================================================
// batch_write: BATCH_SIZE inserts per txn. Tests committed-write throughput.
// ============================================================================

#[bench(group = "compare/batch_write", samples = 10)]
fn batch_write_pagedb(b: &mut Bencher) {
    let bench = pagedb_preloaded();
    let mut rng = make_rng();
    for _ in 0..PRELOAD {
        let _ = random_pair(&mut rng);
    }
    b.iter(|| {
        with_rt(|rt| {
            rt.block_on(async {
                let g = bench.db.lock().await;
                let mut w = g.begin_write().await.unwrap();
                for _ in 0..BATCH_SIZE {
                    let (k, v) = random_pair(&mut rng);
                    w.put(&k, &v).await.unwrap();
                }
                w.commit().await.unwrap();
            })
        })
    });
}

#[bench(group = "compare/batch_write", samples = 10)]
fn batch_write_redb(b: &mut Bencher) {
    let bench = redb_preloaded();
    let mut rng = make_rng();
    for _ in 0..PRELOAD {
        let _ = random_pair(&mut rng);
    }
    b.iter(|| {
        let wx = bench.db.begin_write().unwrap();
        {
            let mut t = wx.open_table(REDB_TABLE).unwrap();
            for _ in 0..BATCH_SIZE {
                let (k, v) = random_pair(&mut rng);
                t.insert(k.as_slice(), v.as_slice()).unwrap();
            }
        }
        wx.commit().unwrap();
    });
}

#[bench(group = "compare/batch_write", samples = 10)]
fn batch_write_rocksdb(b: &mut Bencher) {
    let bench = rocksdb_preloaded();
    let mut rng = make_rng();
    for _ in 0..PRELOAD {
        let _ = random_pair(&mut rng);
    }
    b.iter(|| {
        let txn = bench.db.transaction();
        for _ in 0..BATCH_SIZE {
            let (k, v) = random_pair(&mut rng);
            txn.put(k, v).unwrap();
        }
        txn.commit().unwrap();
    });
}

#[bench(group = "compare/batch_write", samples = 10)]
fn batch_write_sqlite(b: &mut Bencher) {
    let bench = sqlite_preloaded();
    let conn = sqlite_conn(&bench);
    let mut rng = make_rng();
    for _ in 0..PRELOAD {
        let _ = random_pair(&mut rng);
    }
    b.iter(|| {
        let txn = conn.unchecked_transaction().unwrap();
        {
            let mut stmt = txn
                .prepare("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)")
                .unwrap();
            for _ in 0..BATCH_SIZE {
                let (k, v) = random_pair(&mut rng);
                stmt.execute(rusqlite::params![&k[..], &v[..]]).unwrap();
            }
        }
        txn.commit().unwrap();
    });
}

#[compare(
    id = "cmp_batch_write",
    title = "Batch write (BATCH_SIZE keys / txn)",
    benchmarks = [
        "batch_write_pagedb",
        "batch_write_redb",
        "batch_write_rocksdb",
        "batch_write_sqlite"
    ],
    baseline = "batch_write_redb",
    metric = "mean"
)]
struct CmpBatchWrite;

// ============================================================================
// random_read: one get per iter against a preloaded DB.
// ============================================================================

#[bench(group = "compare/random_read")]
fn random_read_pagedb(b: &mut Bencher) {
    let bench = pagedb_preloaded();
    let keys = preloaded_keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = keys[i % keys.len()];
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = bench.db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(&k).await.unwrap())
            })
        })
    });
}

#[bench(group = "compare/random_read")]
fn random_read_redb(b: &mut Bencher) {
    let bench = redb_preloaded();
    let keys = preloaded_keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = keys[i % keys.len()];
        i = i.wrapping_add(1);
        let rx = bench.db.begin_read().unwrap();
        let t = rx.open_table(REDB_TABLE).unwrap();
        black_box(t.get(k.as_slice()).unwrap());
    });
}

#[bench(group = "compare/random_read")]
fn random_read_rocksdb(b: &mut Bencher) {
    let bench = rocksdb_preloaded();
    let keys = preloaded_keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = keys[i % keys.len()];
        i = i.wrapping_add(1);
        let snap = bench.db.snapshot();
        black_box(snap.get(k).unwrap());
    });
}

#[bench(group = "compare/random_read")]
fn random_read_sqlite(b: &mut Bencher) {
    let bench = sqlite_preloaded();
    let conn = sqlite_conn(&bench);
    let mut stmt = conn.prepare("SELECT value FROM kv WHERE key = ?").unwrap();
    let keys = preloaded_keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = keys[i % keys.len()];
        i = i.wrapping_add(1);
        black_box(
            stmt.query_row([&k[..]], |row| row.get::<_, Vec<u8>>(0))
                .ok(),
        );
    });
}

#[compare(
    id = "cmp_random_read",
    title = "Random point read (1 get / txn)",
    benchmarks = [
        "random_read_pagedb",
        "random_read_redb",
        "random_read_rocksdb",
        "random_read_sqlite"
    ],
    baseline = "random_read_redb",
    metric = "mean"
)]
struct CmpRandomRead;

// ============================================================================
// range_read: scan SCAN_LEN entries starting from a random key.
// ============================================================================

#[bench(group = "compare/range_read")]
fn range_read_pagedb(b: &mut Bencher) {
    let bench = pagedb_preloaded();
    let keys = preloaded_keys();
    let end = [0xFFu8; KEY_SIZE];
    let mut i = 0usize;
    b.iter(|| {
        let k = keys[i % keys.len()];
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = bench.db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                let rows = r.scan(&k, &end).await.unwrap();
                black_box(rows.into_iter().take(SCAN_LEN).count())
            })
        })
    });
}

#[bench(group = "compare/range_read")]
fn range_read_redb(b: &mut Bencher) {
    let bench = redb_preloaded();
    let keys = preloaded_keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = keys[i % keys.len()];
        i = i.wrapping_add(1);
        let rx = bench.db.begin_read().unwrap();
        let t = rx.open_table(REDB_TABLE).unwrap();
        let mut iter = t.range(k.as_slice()..).unwrap();
        let mut count = 0;
        for _ in 0..SCAN_LEN {
            if iter.next().is_some() {
                count += 1;
            } else {
                break;
            }
        }
        black_box(count);
    });
}

#[bench(group = "compare/range_read")]
fn range_read_rocksdb(b: &mut Bencher) {
    let bench = rocksdb_preloaded();
    let keys = preloaded_keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = keys[i % keys.len()];
        i = i.wrapping_add(1);
        let snap = bench.db.snapshot();
        let iter = snap.iterator(IteratorMode::From(&k, rocksdb::Direction::Forward));
        black_box(iter.take(SCAN_LEN).count());
    });
}

#[bench(group = "compare/range_read")]
fn range_read_sqlite(b: &mut Bencher) {
    let bench = sqlite_preloaded();
    let conn = sqlite_conn(&bench);
    let mut stmt = conn
        .prepare("SELECT value FROM kv WHERE key >= ? ORDER BY key LIMIT ?")
        .unwrap();
    let keys = preloaded_keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = keys[i % keys.len()];
        i = i.wrapping_add(1);
        let mut rows = stmt
            .query(rusqlite::params![&k[..], SCAN_LEN as i64])
            .unwrap();
        let mut count = 0;
        while rows.next().unwrap().is_some() {
            count += 1;
        }
        black_box(count);
    });
}

#[compare(
    id = "cmp_range_read",
    title = "Random range read (scan SCAN_LEN entries)",
    benchmarks = [
        "range_read_pagedb",
        "range_read_redb",
        "range_read_rocksdb",
        "range_read_sqlite"
    ],
    baseline = "range_read_redb",
    metric = "mean"
)]
struct CmpRangeRead;

fn main() {
    if let Err(e) = fluxbench::run() {
        eprintln!("fluxbench error: {e}");
        std::process::exit(1);
    }
}
