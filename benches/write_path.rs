//! Write-path cost decomposition (fluxbench).
//!
//! Bulk load is the widest gap against other engines, and allocation volume is
//! the strongest signal there: loading rows of ~174 bytes churns roughly a
//! whole 4 KiB page each. Time on this host is unreliable — the machine is
//! shared — but allocation counts are deterministic, so they are what these
//! benchmarks exist to report. Divide the reported totals by [`ROWS`] for the
//! per-row figures.
//!
//! Four shapes, because they exercise different amounts of the path:
//!
//!   - `bulk_put_uncommitted` — descent + leaf mutation only, no commit, no I/O
//!   - `bulk_put`             — the same rows, committed
//!   - `bulk_put_append`      — monotonic keys: the cached-rightmost-path fast path
//!   - `put_one_hot`          — one row into an already-large tree, committed
//!
//! `bulk_put_uncommitted` is the number to optimise against: it is the only one
//! free of `MemVfs` noise. The others commit, and `MemVfs` keeps each file in a
//! `Vec<u8>` it `resize`s, so extending the store reallocates and copies the
//! whole thing. That shows up as large byte counts attributable to the harness
//! rather than to pagedb — most visibly in `put_one_hot`, where a single-row
//! commit appears to allocate megabytes.
//!
//! Run with: `cargo bench --bench write_path`

#![allow(dead_code)] // synthetic placeholder structs

use std::hint::black_box;

use fluxbench::prelude::*;
use fluxbench::{TrackingAllocator, bench};

use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{CipherId, Db, OpenOptions, RealmId, RetainPolicy};

/// `flux.toml` turns allocation tracking on; without the tracking allocator
/// installed here every benchmark in this binary reports zero bytes.
#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

const PAGE: usize = 4096;
/// Rows per measured transaction. Large enough that the tree is several levels
/// deep — per-row cost grows with depth, so a tiny tree would flatter the
/// numbers — and small enough to keep a sample under a second.
const ROWS: usize = 10_000;
const KEY_SIZE: usize = 24;
const VALUE_SIZE: usize = 150;

thread_local! {
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
}

fn with_rt<R>(f: impl FnOnce(&tokio::runtime::Runtime) -> R) -> R {
    RT.with(|rt| f(rt))
}

fn bench_opts() -> OpenOptions {
    // Match the cross-engine suites: history retention pins every superseded
    // page, which would make a sustained write bench measure history growth.
    OpenOptions::default()
        .with_commit_history_retain(RetainPolicy::Disabled)
        .with_cipher(CipherId::Aes256Gcm)
        .with_anchor_budget(10_000_000)
}

async fn open_mem() -> Db<MemVfs> {
    Db::open(
        MemVfs::new(),
        [7u8; 32],
        PAGE,
        RealmId::new([3u8; 16]),
        bench_opts(),
    )
    .await
    .unwrap()
}

/// Deterministic pseudo-random key, so runs are comparable without an RNG in
/// the measured region.
fn scrambled_key(i: usize) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    let mixed = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    key[..8].copy_from_slice(&mixed.to_be_bytes());
    key[8..16].copy_from_slice(&(i as u64).to_le_bytes());
    key
}

fn monotonic_key(i: usize) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    key[..8].copy_from_slice(&(i as u64).to_be_bytes());
    key
}

fn value() -> Vec<u8> {
    vec![0xA5u8; VALUE_SIZE]
}

/// Control for [`bulk_put_uncommitted`]: identical shape with zero rows, so
/// its totals are whatever opening a store and a transaction costs. Subtract it
/// before dividing by [`ROWS`], or per-row figures silently carry the setup.
#[bench(group = "btree/write-path", samples = 10)]
fn bulk_put_no_rows(b: &mut Bencher) {
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem())),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let w = db.begin_write().await.unwrap();
                    w.abort().await;
                })
            })
        },
    );
}

/// Descent and leaf mutation with no commit: the transaction is abandoned, so
/// nothing reaches the pager or the VFS. This isolates the per-row cost the
/// tree itself imposes.
#[bench(group = "btree/write-path", samples = 10)]
fn bulk_put_uncommitted(b: &mut Bencher) {
    let v = value();
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem())),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let mut w = db.begin_write().await.unwrap();
                    for i in 0..ROWS {
                        w.put(&scrambled_key(i), &v).await.unwrap();
                    }
                    w.abort().await;
                })
            })
        },
    );
}

/// Unsorted bulk load: `ROWS` rows in one transaction, fresh store per sample.
#[bench(group = "btree/write-path", samples = 10)]
fn bulk_put(b: &mut Bencher) {
    let v = value();
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem())),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let mut w = db.begin_write().await.unwrap();
                    for i in 0..ROWS {
                        w.put(&scrambled_key(i), &v).await.unwrap();
                    }
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

/// Monotonic bulk load, which takes the cached-rightmost-path fast path.
#[bench(group = "btree/write-path", samples = 10)]
fn bulk_put_append(b: &mut Bencher) {
    let v = value();
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem())),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let mut w = db.begin_write().await.unwrap();
                    for i in 0..ROWS {
                        w.put_append(&monotonic_key(i), &v).await.unwrap();
                    }
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

/// Per-row cost against transaction size.
///
/// A single transaction should cost time linear in the rows it carries, so
/// dividing each result by its row count should give a flat line. A rising one
/// means per-row work that grows with the rows already staged.
#[bench(group = "btree/write-path/scaling", args = [2500, 5000, 10000, 20000], samples = 5)]
fn scaling_uncommitted(b: &mut Bencher, rows: u32) {
    let v = value();
    let rows = rows as usize;
    b.iter_with_setup(
        || with_rt(|rt| rt.block_on(open_mem())),
        |db| {
            with_rt(|rt| {
                rt.block_on(async {
                    let mut w = db.begin_write().await.unwrap();
                    for i in 0..rows {
                        w.put(&scrambled_key(i), &v).await.unwrap();
                    }
                    w.abort().await;
                })
            })
        },
    );
}

/// Per-row cost against transaction size for the committed file-backed load —
/// the shape the cross-engine bulk-load benchmark runs. Rising per-row cost
/// here, where [`scaling_uncommitted`] stays flat, isolates the growth to
/// commit rather than to the tree.
#[bench(group = "btree/write-path/scaling", args = [10000, 25000, 50000, 100000], samples = 3)]
fn scaling_file_committed(b: &mut Bencher, rows: u32) {
    let v = value();
    let rows = rows as usize;
    b.iter_with_setup(
        || {
            let dir = tempfile::TempDir::new().unwrap();
            let db = with_rt(|rt| {
                rt.block_on(async {
                    Db::open(
                        TokioVfs::new(dir.path()),
                        [7u8; 32],
                        PAGE,
                        RealmId::new([3u8; 16]),
                        bench_opts(),
                    )
                    .await
                    .unwrap()
                })
            });
            (db, dir)
        },
        |(db, _keep)| {
            with_rt(|rt| {
                rt.block_on(async {
                    let mut w = db.begin_write().await.unwrap();
                    for i in 0..rows {
                        w.put(&scrambled_key(i), &v).await.unwrap();
                    }
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

/// The same load against a real file backend, so AEAD over every dirty page
/// and the page writes themselves are in the measurement.
///
/// This is the shape that matches the cross-engine bulk-load workload. The
/// `MemVfs` variants above isolate the in-memory tree; the distance between
/// them and this one *is* the commit path.
#[bench(group = "btree/write-path", samples = 10)]
fn bulk_put_file(b: &mut Bencher) {
    let v = value();
    b.iter_with_setup(
        || {
            let dir = tempfile::TempDir::new().unwrap();
            let db = with_rt(|rt| {
                rt.block_on(async {
                    Db::open(
                        TokioVfs::new(dir.path()),
                        [7u8; 32],
                        PAGE,
                        RealmId::new([3u8; 16]),
                        bench_opts(),
                    )
                    .await
                    .unwrap()
                })
            });
            (db, dir)
        },
        |(db, _keep)| {
            with_rt(|rt| {
                rt.block_on(async {
                    let mut w = db.begin_write().await.unwrap();
                    for i in 0..ROWS {
                        w.put(&scrambled_key(i), &v).await.unwrap();
                    }
                    w.commit().await.unwrap();
                })
            })
        },
    );
}

/// One `put` into an already-large tree, with no commit, isolating descent and
/// leaf mutation from commit cost.
#[bench(group = "btree/write-path", samples = 50)]
fn put_one_hot(b: &mut Bencher) {
    let v = value();
    let db = with_rt(|rt| {
        rt.block_on(async {
            let db = open_mem().await;
            let mut w = db.begin_write().await.unwrap();
            for i in 0..ROWS {
                w.put(&scrambled_key(i), &v).await.unwrap();
            }
            w.commit().await.unwrap();
            db
        })
    });
    let mut i = ROWS;
    b.iter(|| {
        let k = scrambled_key(i);
        i += 1;
        with_rt(|rt| {
            rt.block_on(async {
                let mut w = db.begin_write().await.unwrap();
                w.put(&k, &v).await.unwrap();
                black_box(w.commit().await.unwrap())
            })
        })
    });
}

fn main() {
    if let Err(e) = fluxbench::run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
