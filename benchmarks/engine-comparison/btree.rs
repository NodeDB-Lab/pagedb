//! pagedb B+ tree benchmarks (fluxbench).
//!
//! Levels the playing field with redb across three axes:
//!   - substrate: in-memory (`MemVfs`) vs file-backed (`TokioVfs` / tempfile)
//!   - security:  AEAD (AES-256-GCM) vs Plaintext+MAC (cipher_id=0)
//!   - workload:  one txn per op vs batched / shared txn
//!
//! redb has no encryption — comparing redb vs `pagedb-aead` measures the cost
//! of the threat model; comparing redb vs `pagedb-plain` isolates the
//! structural cost (CoW shadow paging, AAD, MAC-only, durable reader pins).
//!
//! Run with: `cargo bench -p pagedb-engine-comparison --bench btree`

#![allow(dead_code)] // verify/synthetic/compare placeholder structs

use std::cell::RefCell;
use std::hint::black_box;
use std::rc::Rc;
use std::sync::Arc;

use fluxbench::prelude::*;
use fluxbench::{TrackingAllocator, bench, compare, synthetic, verify};
use tokio::sync::Mutex as AsyncMutex;

use pagedb::vfs::Vfs;
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{CipherId, Db, OpenOptions, RealmId, RetainPolicy};

/// `flux.toml` turns allocation tracking on; without the tracking allocator
/// installed here every benchmark in this binary reports zero bytes.
#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

const PAGE: usize = 4096;
/// Working-set size: number of keys preloaded for read benches and the
/// transaction-size for batched inserts.
const N: usize = 1_000;
const VALUE: &[u8] = b"bench-value-0123456789abcdef";

// --- harness ----------------------------------------------------------------

fn key(i: usize) -> Vec<u8> {
    format!("bench:{i:08}").into_bytes()
}

fn bench_opts() -> OpenOptions {
    // Fair-comparison: redb has no equivalent commit-history index; disable
    // pagedb's so the bench measures the same feature surface. Retaining it
    // `Unbounded` also pins every superseded page for the life of the handle,
    // so a sustained per-txn write bench measures unbounded history growth
    // rather than commit cost — the drift shows up directly as per-iteration
    // times that climb the longer the bench runs.
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)
}

/// Each `(cipher, substrate)` variant gets its own preloaded Db kept alive
/// in a thread-local across all the iterations of the benches that use it.
/// This matches fluxbench's per-worker model: setup once, run many iterations.
type SharedDb<V> = Arc<AsyncMutex<Db<V>>>;

thread_local! {
    static MEM_AEAD:   RefCell<Option<SharedDb<MemVfs>>>   = const { RefCell::new(None) };
    static MEM_PLAIN:  RefCell<Option<SharedDb<MemVfs>>>   = const { RefCell::new(None) };
    static FILE_AEAD:  RefCell<Option<SharedDb<TokioVfs>>> = const { RefCell::new(None) };
    static FILE_PLAIN: RefCell<Option<SharedDb<TokioVfs>>> = const { RefCell::new(None) };
    // Keep the TempDirs alive for the lifetime of the file-backed DBs.
    static KEEP_DIRS:  RefCell<Vec<tempfile::TempDir>>     = const { RefCell::new(Vec::new()) };
    /// Lookup keys, built once. Calling `key()` inside a timed closure would
    /// charge a `format!` and a heap allocation to every sample — tens of
    /// nanoseconds against a sub-microsecond lookup, for every engine.
    static KEYS: RefCell<Option<Rc<Vec<Vec<u8>>>>> = const { RefCell::new(None) };
}

fn keys() -> Rc<Vec<Vec<u8>>> {
    KEYS.with(|cell| {
        if cell.borrow().is_none() {
            *cell.borrow_mut() = Some(Rc::new((0..N).map(key).collect()));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

async fn open_mem(cipher: CipherId, seed: u8) -> SharedDb<MemVfs> {
    let db = Db::open(
        MemVfs::new(),
        [seed; 32],
        PAGE,
        RealmId::new([seed; 16]),
        bench_opts().with_cipher(cipher),
    )
    .await
    .unwrap();
    Arc::new(AsyncMutex::new(db))
}

async fn open_file(cipher: CipherId, seed: u8) -> (SharedDb<TokioVfs>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let vfs = TokioVfs::new(dir.path());
    let db = Db::open(
        vfs,
        [seed; 32],
        PAGE,
        RealmId::new([seed; 16]),
        bench_opts().with_cipher(cipher),
    )
    .await
    .unwrap();
    (Arc::new(AsyncMutex::new(db)), dir)
}

/// Preload `N` keys into the DB. Called once per variant.
async fn preload<V: Vfs + Clone + 'static>(db: &SharedDb<V>) {
    let g = db.lock().await;
    let mut w = g.begin_write().await.unwrap();
    for i in 0..N {
        w.put(&key(i), VALUE).await.unwrap();
    }
    w.commit().await.unwrap();
}

fn mem_aead(rt: &tokio::runtime::Runtime) -> SharedDb<MemVfs> {
    MEM_AEAD.with(|cell| {
        if cell.borrow().is_none() {
            let db = rt.block_on(open_mem(CipherId::Aes256Gcm, 1));
            rt.block_on(preload(&db));
            *cell.borrow_mut() = Some(db);
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

fn mem_plain(rt: &tokio::runtime::Runtime) -> SharedDb<MemVfs> {
    MEM_PLAIN.with(|cell| {
        if cell.borrow().is_none() {
            let db = rt.block_on(open_mem(CipherId::PlaintextMac, 2));
            rt.block_on(preload(&db));
            *cell.borrow_mut() = Some(db);
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

fn file_aead(rt: &tokio::runtime::Runtime) -> SharedDb<TokioVfs> {
    FILE_AEAD.with(|cell| {
        if cell.borrow().is_none() {
            let (db, dir) = rt.block_on(open_file(CipherId::Aes256Gcm, 3));
            rt.block_on(preload(&db));
            KEEP_DIRS.with(|d| d.borrow_mut().push(dir));
            *cell.borrow_mut() = Some(db);
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

fn file_plain(rt: &tokio::runtime::Runtime) -> SharedDb<TokioVfs> {
    FILE_PLAIN.with(|cell| {
        if cell.borrow().is_none() {
            let (db, dir) = rt.block_on(open_file(CipherId::PlaintextMac, 4));
            rt.block_on(preload(&db));
            KEEP_DIRS.with(|d| d.borrow_mut().push(dir));
            *cell.borrow_mut() = Some(db);
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

// Per-iteration tokio runtime helper: build once, reuse across iters.
thread_local! {
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
}

fn with_rt<R>(f: impl FnOnce(&tokio::runtime::Runtime) -> R) -> R {
    RT.with(|rt| f(rt))
}

// --- get: one read txn per get (non-abortable, no durable-pin write) --------

#[bench(group = "btree/get/per-txn")]
fn get_per_txn_mem_aead(b: &mut Bencher) {
    let db = with_rt(mem_aead);
    let keys = keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = &keys[i % N];
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(k).await.unwrap())
            })
        })
    });
}

#[bench(group = "btree/get/per-txn")]
fn get_per_txn_mem_plain(b: &mut Bencher) {
    let db = with_rt(mem_plain);
    let keys = keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = &keys[i % N];
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(k).await.unwrap())
            })
        })
    });
}

#[bench(group = "btree/get/per-txn")]
fn get_per_txn_file_aead(b: &mut Bencher) {
    let db = with_rt(file_aead);
    let keys = keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = &keys[i % N];
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(k).await.unwrap())
            })
        })
    });
}

#[bench(group = "btree/get/per-txn")]
fn get_per_txn_file_plain(b: &mut Bencher) {
    let db = with_rt(file_plain);
    let keys = keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = &keys[i % N];
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(k).await.unwrap())
            })
        })
    });
}

// --- redb baseline ----------------------------------------------------------

thread_local! {
    static REDB_DB: RefCell<Option<(Arc<redb::Database>, tempfile::TempDir)>>
        = const { RefCell::new(None) };
}

fn redb_db() -> Arc<redb::Database> {
    REDB_DB.with(|cell| {
        if cell.borrow().is_none() {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("bench.redb");
            let db = redb::Database::create(&path).unwrap();
            let table_def: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("kv");
            let wx = db.begin_write().unwrap();
            {
                let mut t = wx.open_table(table_def).unwrap();
                for i in 0..N {
                    t.insert(key(i).as_slice(), VALUE).unwrap();
                }
            }
            wx.commit().unwrap();
            *cell.borrow_mut() = Some((Arc::new(db), dir));
        }
        cell.borrow().as_ref().unwrap().0.clone()
    })
}

#[bench(group = "btree/get/per-txn")]
fn get_per_txn_redb(b: &mut Bencher) {
    let db = redb_db();
    let table_def: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("kv");
    let keys = keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = &keys[i % N];
        i = i.wrapping_add(1);
        let rx = db.begin_read().unwrap();
        let t = rx.open_table(table_def).unwrap();
        black_box(t.get(k.as_slice()).unwrap());
    });
}

// --- insert: one committed txn per put --------------------------------------
//
// Steady state, against an already-populated tree, inserting a fresh key each
// iteration. Opening a virgin database in setup and timing a single commit
// into it instead measures database *initialisation* — dominated by first-write
// file preallocation, which differs wildly between engines — and reports it as
// per-transaction insert latency.
//
// These use their own databases rather than the ones the read benches share:
// workers are persistent, so mutating a shared tree would make the read results
// depend on benchmark execution order.

thread_local! {
    static W_MEM_AEAD:  RefCell<Option<SharedDb<MemVfs>>>   = const { RefCell::new(None) };
    static W_MEM_PLAIN: RefCell<Option<SharedDb<MemVfs>>>   = const { RefCell::new(None) };
    static W_FILE_AEAD: RefCell<Option<SharedDb<TokioVfs>>> = const { RefCell::new(None) };
    static W_REDB:      RefCell<Option<Arc<redb::Database>>> = const { RefCell::new(None) };
}

fn w_mem_aead(rt: &tokio::runtime::Runtime) -> SharedDb<MemVfs> {
    W_MEM_AEAD.with(|cell| {
        if cell.borrow().is_none() {
            let db = rt.block_on(open_mem(CipherId::Aes256Gcm, 11));
            rt.block_on(preload(&db));
            *cell.borrow_mut() = Some(db);
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

fn w_mem_plain(rt: &tokio::runtime::Runtime) -> SharedDb<MemVfs> {
    W_MEM_PLAIN.with(|cell| {
        if cell.borrow().is_none() {
            let db = rt.block_on(open_mem(CipherId::PlaintextMac, 12));
            rt.block_on(preload(&db));
            *cell.borrow_mut() = Some(db);
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

fn w_file_aead(rt: &tokio::runtime::Runtime) -> SharedDb<TokioVfs> {
    W_FILE_AEAD.with(|cell| {
        if cell.borrow().is_none() {
            let (db, dir) = rt.block_on(open_file(CipherId::Aes256Gcm, 13));
            rt.block_on(preload(&db));
            KEEP_DIRS.with(|d| d.borrow_mut().push(dir));
            *cell.borrow_mut() = Some(db);
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

fn w_redb() -> Arc<redb::Database> {
    W_REDB.with(|cell| {
        if cell.borrow().is_none() {
            let dir = tempfile::TempDir::new().unwrap();
            let db = redb::Database::create(dir.path().join("w.redb")).unwrap();
            let table_def: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("kv");
            let wx = db.begin_write().unwrap();
            {
                let mut t = wx.open_table(table_def).unwrap();
                for i in 0..N {
                    t.insert(key(i).as_slice(), VALUE).unwrap();
                }
            }
            wx.commit().unwrap();
            KEEP_DIRS.with(|d| d.borrow_mut().push(dir));
            *cell.borrow_mut() = Some(Arc::new(db));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

#[bench(group = "btree/insert/per-txn")]
fn insert_per_txn_mem_aead(b: &mut Bencher) {
    let db = with_rt(w_mem_aead);
    let mut i = N;
    b.iter(|| {
        let k = key(i);
        i += 1;
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let mut w = g.begin_write().await.unwrap();
                w.put(&k, VALUE).await.unwrap();
                w.commit().await.unwrap();
            })
        })
    });
}

#[bench(group = "btree/insert/per-txn")]
fn insert_per_txn_mem_plain(b: &mut Bencher) {
    let db = with_rt(w_mem_plain);
    let mut i = N;
    b.iter(|| {
        let k = key(i);
        i += 1;
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let mut w = g.begin_write().await.unwrap();
                w.put(&k, VALUE).await.unwrap();
                w.commit().await.unwrap();
            })
        })
    });
}

#[bench(group = "btree/insert/per-txn")]
fn insert_per_txn_file_aead(b: &mut Bencher) {
    let db = with_rt(w_file_aead);
    let mut i = N;
    b.iter(|| {
        let k = key(i);
        i += 1;
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let mut w = g.begin_write().await.unwrap();
                w.put(&k, VALUE).await.unwrap();
                w.commit().await.unwrap();
            })
        })
    });
}

#[bench(group = "btree/insert/per-txn")]
fn insert_per_txn_redb(b: &mut Bencher) {
    let db = w_redb();
    let table_def: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("kv");
    let mut i = N;
    b.iter(|| {
        let k = key(i);
        i += 1;
        let wx = db.begin_write().unwrap();
        {
            let mut t = wx.open_table(table_def).unwrap();
            t.insert(k.as_slice(), VALUE).unwrap();
        }
        wx.commit().unwrap();
    });
}

// --- batched insert: N keys / 1 txn (amortizes commit overhead) -------------
//
// Unlike the per-txn group above these deliberately load into a fresh database:
// bulk-loading an empty tree is the workload. First-write file preallocation is
// still in the measurement, but amortised across N keys rather than charged to
// a single commit.

#[bench(group = "btree/insert/batched")]
fn insert_batched_mem_aead(b: &mut Bencher) {
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem(CipherId::Aes256Gcm, 21))),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let g = db.lock().await;
                    let mut w = g.begin_write().await.unwrap();
                    for i in 0..N {
                        w.put(&key(i), VALUE).await.unwrap();
                    }
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

#[bench(group = "btree/insert/batched")]
fn insert_batched_mem_plain(b: &mut Bencher) {
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem(CipherId::PlaintextMac, 22))),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let g = db.lock().await;
                    let mut w = g.begin_write().await.unwrap();
                    for i in 0..N {
                        w.put(&key(i), VALUE).await.unwrap();
                    }
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

#[bench(group = "btree/insert/batched")]
fn insert_batched_redb(b: &mut Bencher) {
    b.iter_with_setup(
        || {
            let dir = tempfile::TempDir::new().unwrap();
            let db = redb::Database::create(dir.path().join("b.redb")).unwrap();
            (db, dir)
        },
        |(db, _keep)| {
            let table_def: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("kv");
            let wx = db.begin_write().unwrap();
            {
                let mut t = wx.open_table(table_def).unwrap();
                for i in 0..N {
                    t.insert(key(i).as_slice(), VALUE).unwrap();
                }
            }
            wx.commit().unwrap();
        },
    );
}

// --- verification & synthetic metrics ---------------------------------------

#[verify(
    expr = "get_per_txn_mem_aead < 10 * get_per_txn_redb",
    severity = "warning"
)]
struct PagedbReadsWithin10xRedb;

#[verify(expr = "get_per_txn_mem_aead < 5000", severity = "warning")]
struct PagedbReadsUnder5us;

#[synthetic(
    id = "aead_overhead_read",
    formula = "get_per_txn_mem_aead / get_per_txn_mem_plain",
    unit = "x"
)]
struct AeadReadOverhead;

#[synthetic(
    id = "vs_redb_read",
    formula = "get_per_txn_mem_aead / get_per_txn_redb",
    unit = "x"
)]
struct VsRedbRead;

#[synthetic(
    id = "vs_redb_insert_batched",
    formula = "insert_batched_mem_aead / insert_batched_redb",
    unit = "x"
)]
struct VsRedbBatchInsert;

#[compare(
    id = "get_compare",
    title = "Point get (1 txn per get)",
    benchmarks = [
        "get_per_txn_mem_aead",
        "get_per_txn_mem_plain",
        "get_per_txn_file_aead",
        "get_per_txn_file_plain",
        "get_per_txn_redb"
    ],
    baseline = "get_per_txn_redb",
    metric = "mean"
)]
struct GetCompare;

#[compare(
    id = "insert_batched_compare",
    title = "Batched insert (N keys / 1 txn)",
    benchmarks = [
        "insert_batched_mem_aead",
        "insert_batched_mem_plain",
        "insert_batched_redb"
    ],
    baseline = "insert_batched_redb",
    metric = "mean"
)]
struct InsertBatchedCompare;

fn main() {
    if let Err(e) = fluxbench::run() {
        eprintln!("fluxbench error: {e}");
        std::process::exit(1);
    }
}
