//! Read-path cost decomposition (fluxbench).
//!
//! `get` on a warm cache should be dominated by the B+ tree descent, not by
//! transaction bookkeeping. This suite separates the two so a regression in
//! either is attributable on its own:
//!
//!   - `txn_open_close`     — `begin_read` + drop, no lookup at all
//!   - `get_shared_txn`     — lookup only; the txn cost is amortised away
//!   - `get_per_txn`        — lookup with a fresh txn, the embedder-facing path
//!
//! `get_per_txn - get_shared_txn` is the per-transaction overhead, and
//! `txn_open_close` attributes it to open/close rather than to the descent.
//!
//! Run with: `cargo bench --bench read_path`

#![allow(dead_code)] // synthetic/verify placeholder structs

use std::cell::RefCell;
use std::hint::black_box;
use std::rc::Rc;

use fluxbench::prelude::*;
use fluxbench::{TrackingAllocator, bench, synthetic};

use pagedb::vfs::memory::MemVfs;
use pagedb::{CipherId, Db, OpenOptions, RealmId, RetainPolicy};

/// `flux.toml` turns allocation tracking on; without the tracking allocator
/// installed here every benchmark in this binary reports zero bytes.
#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

const PAGE: usize = 4096;
/// Working-set size. Sized to stay resident in the buffer pool so the
/// measurement isolates in-memory descent cost, not cache-miss I/O.
const N: usize = 1_000;
const VALUE: &[u8] = b"bench-value-0123456789abcdef";

fn key(i: usize) -> Vec<u8> {
    format!("bench:{i:08}").into_bytes()
}

thread_local! {
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    static DB: RefCell<Option<Rc<Db<MemVfs>>>> = const { RefCell::new(None) };
    /// Keys are built once: `format!` in the timed closure would charge an
    /// allocation to every sample and swamp a sub-microsecond lookup.
    static KEYS: RefCell<Option<Rc<Vec<Vec<u8>>>>> = const { RefCell::new(None) };
}

fn with_rt<R>(f: impl FnOnce(&tokio::runtime::Runtime) -> R) -> R {
    RT.with(|rt| f(rt))
}

fn keys() -> Rc<Vec<Vec<u8>>> {
    KEYS.with(|cell| {
        if cell.borrow().is_none() {
            *cell.borrow_mut() = Some(Rc::new((0..N).map(key).collect()));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

/// Preloaded, warm-cache database shared by every benchmark in this file.
/// Reads take `&self`, so no lock wrapper is needed — adding one would put
/// mutex traffic inside the measurement.
fn db() -> Rc<Db<MemVfs>> {
    DB.with(|cell| {
        if cell.borrow().is_none() {
            let db = with_rt(|rt| {
                rt.block_on(async {
                    let db = Db::open(
                        MemVfs::new(),
                        [1u8; 32],
                        PAGE,
                        RealmId::new([1u8; 16]),
                        OpenOptions::default()
                            .with_commit_history_retain(RetainPolicy::Unbounded)
                            .with_cipher(CipherId::Aes256Gcm),
                    )
                    .await
                    .unwrap();
                    let mut w = db.begin_write().await.unwrap();
                    for i in 0..N {
                        w.put(&key(i), VALUE).await.unwrap();
                    }
                    w.commit().await.unwrap();
                    db
                })
            });
            *cell.borrow_mut() = Some(Rc::new(db));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

#[bench(group = "pager/read-path")]
fn txn_open_close(b: &mut Bencher) {
    let db = db();
    b.iter(|| {
        with_rt(|rt| {
            rt.block_on(async {
                let r = db.begin_read_non_abortable().await.unwrap();
                black_box(r.commit_id())
            })
        })
    });
}

#[bench(group = "pager/read-path")]
fn get_shared_txn(b: &mut Bencher) {
    let db = db();
    let keys = keys();
    let mut i = 0usize;
    // Opened once, outside the timed closure, so each sample charges only the
    // descent. Built via `block_on` here and awaited via `block_on` below —
    // never nested, which would panic.
    let r = with_rt(|rt| rt.block_on(async { db.begin_read_non_abortable().await.unwrap() }));
    b.iter(|| {
        let k = &keys[i % N];
        i = i.wrapping_add(1);
        with_rt(|rt| rt.block_on(async { black_box(r.get(k).await.unwrap()) }))
    });
}

#[bench(group = "pager/read-path")]
fn get_per_txn(b: &mut Bencher) {
    let db = db();
    let keys = keys();
    let mut i = 0usize;
    b.iter(|| {
        let k = &keys[i % N];
        i = i.wrapping_add(1);
        with_rt(|rt| {
            rt.block_on(async {
                let r = db.begin_read_non_abortable().await.unwrap();
                black_box(r.get(k).await.unwrap())
            })
        })
    });
}

#[synthetic(
    id = "txn_overhead_per_get",
    formula = "get_per_txn - get_shared_txn",
    unit = "ns"
)]
struct TxnOverheadPerGet;

fn main() {
    if let Err(e) = fluxbench::run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
