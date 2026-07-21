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
use std::sync::Arc;

use fluxbench::prelude::*;
use fluxbench::{bench, compare, synthetic, verify};
use tokio::sync::Mutex as AsyncMutex;

use pagedb::crypto::CipherId;
use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::vfs::Vfs;
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{Db, RealmId};

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
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded)
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
}

async fn open_mem(cipher: CipherId, seed: u8) -> SharedDb<MemVfs> {
    let db = Db::open_internal_with_options_and_cipher(
        MemVfs::new(),
        [seed; 32],
        PAGE,
        RealmId::new([seed; 16]),
        bench_opts(),
        cipher,
    )
    .await
    .unwrap();
    Arc::new(AsyncMutex::new(db))
}

async fn open_file(cipher: CipherId, seed: u8) -> (SharedDb<TokioVfs>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let vfs = TokioVfs::new(dir.path());
    let db = Db::open_internal_with_options_and_cipher(
        vfs,
        [seed; 32],
        PAGE,
        RealmId::new([seed; 16]),
        bench_opts(),
        cipher,
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
    let mut i = 0usize;
    b.iter(|| {
        let k = key(i % N);
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(&k).await.unwrap())
            })
        })
    });
}

#[bench(group = "btree/get/per-txn")]
fn get_per_txn_mem_plain(b: &mut Bencher) {
    let db = with_rt(mem_plain);
    let mut i = 0usize;
    b.iter(|| {
        let k = key(i % N);
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(&k).await.unwrap())
            })
        })
    });
}

#[bench(group = "btree/get/per-txn")]
fn get_per_txn_file_aead(b: &mut Bencher) {
    let db = with_rt(file_aead);
    let mut i = 0usize;
    b.iter(|| {
        let k = key(i % N);
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(&k).await.unwrap())
            })
        })
    });
}

#[bench(group = "btree/get/per-txn")]
fn get_per_txn_file_plain(b: &mut Bencher) {
    let db = with_rt(file_plain);
    let mut i = 0usize;
    b.iter(|| {
        let k = key(i % N);
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let r = g.begin_read_non_abortable().await.unwrap();
                black_box(r.get(&k).await.unwrap())
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
    let mut i = 0usize;
    b.iter(|| {
        let k = key(i % N);
        i = i.wrapping_add(1);
        let rx = db.begin_read().unwrap();
        let t = rx.open_table(table_def).unwrap();
        black_box(t.get(k.as_slice()).unwrap());
    });
}

// --- insert: one committed txn per put --------------------------------------

#[bench(group = "btree/insert/per-txn")]
fn insert_per_txn_mem_aead(b: &mut Bencher) {
    // Each iter opens a fresh DB so the tree doesn't grow unbounded.
    // The DB is reused across iters within a batch via iter_with_setup.
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem(CipherId::Aes256Gcm, 11))),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let g = db.lock().await;
                    let mut w = g.begin_write().await.unwrap();
                    w.put(b"k", VALUE).await.unwrap();
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

#[bench(group = "btree/insert/per-txn")]
fn insert_per_txn_mem_plain(b: &mut Bencher) {
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem(CipherId::PlaintextMac, 12))),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let g = db.lock().await;
                    let mut w = g.begin_write().await.unwrap();
                    w.put(b"k", VALUE).await.unwrap();
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

#[bench(group = "btree/insert/per-txn")]
fn insert_per_txn_file_aead(b: &mut Bencher) {
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_file(CipherId::Aes256Gcm, 13))),
        |(db, _keep)| {
            with_rt(|rt| {
                rt.block_on(async {
                    let g = db.lock().await;
                    let mut w = g.begin_write().await.unwrap();
                    w.put(b"k", VALUE).await.unwrap();
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

#[bench(group = "btree/insert/per-txn")]
fn insert_per_txn_redb(b: &mut Bencher) {
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
                t.insert(b"k".as_slice(), VALUE).unwrap();
            }
            wx.commit().unwrap();
        },
    );
}

// --- batched insert: N keys / 1 txn (amortizes commit overhead) -------------

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
