//! pagedb Segment benchmarks (fluxbench): `SegmentWriter` append + seal vs
//! baselines that strip pieces of the stack to isolate the cost of each layer.
//!
//! Run with: `cargo bench --bench segment`

#![allow(dead_code)] // verify/synthetic/compare placeholder structs

use std::cell::RefCell;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce as AesNonce};
use fluxbench::prelude::*;
use fluxbench::{bench, compare, synthetic};
use tokio::sync::Mutex as AsyncMutex;

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;
/// Payload bytes per page (must fit inside `page_size - envelope_overhead`).
const PAYLOAD_LEN: usize = 4000;
/// Pages appended per segment per iteration.
const PAGES_PER_SEG: usize = 128;

thread_local! {
    static DB: RefCell<Option<Arc<AsyncMutex<Db<MemVfs>>>>> = const { RefCell::new(None) };
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
}

fn with_rt<R>(f: impl FnOnce(&tokio::runtime::Runtime) -> R) -> R {
    RT.with(|rt| f(rt))
}

fn shared_db() -> Arc<AsyncMutex<Db<MemVfs>>> {
    DB.with(|cell| {
        if cell.borrow().is_none() {
            let db = with_rt(|rt| {
                rt.block_on(async {
                    Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, RealmId::new([1; 16]))
                        .await
                        .unwrap()
                })
            });
            *cell.borrow_mut() = Some(Arc::new(AsyncMutex::new(db)));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

// --- pagedb: full append + seal through the writer --------------------------

#[bench(group = "segment/append_seal")]
fn pagedb_append_seal(b: &mut Bencher) {
    let db = shared_db();
    let payload = vec![0xABu8; PAYLOAD_LEN];
    let realm = RealmId::new([1; 16]);

    b.iter(|| {
        with_rt(|rt| {
            rt.block_on(async {
                let g = db.lock().await;
                let mut w = g
                    .create_segment(realm, SegmentKind::Unspecified)
                    .await
                    .unwrap();
                for _ in 0..PAGES_PER_SEG {
                    w.append_page(SegmentPageKind::Data, &payload)
                        .await
                        .unwrap();
                }
                let _ = w.seal().await.unwrap();
            })
        })
    });
}

// --- baseline: AES-GCM only (CPU floor, no I/O) -----------------------------

#[bench(group = "segment/append_seal")]
fn baseline_aesgcm_only(b: &mut Bencher) {
    let key_bytes = [0x42u8; 32];
    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let payload = vec![0xABu8; PAYLOAD_LEN];
    let mut iter_idx: u64 = 0;

    b.iter(|| {
        iter_idx = iter_idx.wrapping_add(1);
        for p in 0..PAGES_PER_SEG as u64 {
            let mut n = [0u8; 12];
            let v = iter_idx.wrapping_mul(PAGES_PER_SEG as u64).wrapping_add(p);
            n[..8].copy_from_slice(&v.to_le_bytes());
            let nonce = AesNonce::from_slice(&n);
            let _ = cipher.encrypt(nonce, payload.as_slice()).unwrap();
        }
    });
}

// --- baseline: raw tokio::fs write + AES-GCM (no pagedb stack) --------------

#[bench(group = "segment/append_seal")]
fn baseline_fs_write_aesgcm(b: &mut Bencher) {
    use tokio::io::AsyncWriteExt;

    let key_bytes = [0x42u8; 32];
    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let payload = vec![0xABu8; PAYLOAD_LEN];
    let dir = tempfile::TempDir::new().unwrap();
    let mut iter_idx: u64 = 0;

    b.iter(|| {
        iter_idx = iter_idx.wrapping_add(1);
        let path = dir.path().join(format!("seg-{iter_idx}.bin"));
        with_rt(|rt| {
            rt.block_on(async {
                let mut file = tokio::fs::File::create(&path).await.unwrap();
                for p in 0..PAGES_PER_SEG as u64 {
                    let mut n = [0u8; 12];
                    let v = iter_idx.wrapping_mul(PAGES_PER_SEG as u64).wrapping_add(p);
                    n[..8].copy_from_slice(&v.to_le_bytes());
                    let nonce = AesNonce::from_slice(&n);
                    let ct = cipher.encrypt(nonce, payload.as_slice()).unwrap();
                    file.write_all(&ct).await.unwrap();
                }
                file.flush().await.unwrap();
            })
        })
    });
}

#[synthetic(
    id = "writer_overhead_vs_aesgcm",
    formula = "pagedb_append_seal / baseline_aesgcm_only",
    unit = "x"
)]
struct WriterOverheadVsAesGcm;

#[synthetic(
    id = "writer_overhead_vs_fs_write",
    formula = "pagedb_append_seal / baseline_fs_write_aesgcm",
    unit = "x"
)]
struct WriterOverheadVsFsWrite;

#[compare(
    id = "segment_compare",
    title = "Segment append+seal vs raw baselines",
    benchmarks = [
        "pagedb_append_seal",
        "baseline_aesgcm_only",
        "baseline_fs_write_aesgcm"
    ],
    baseline = "baseline_aesgcm_only",
    metric = "mean"
)]
struct SegmentCompare;

fn main() {
    if let Err(e) = fluxbench::run() {
        eprintln!("fluxbench error: {e}");
        std::process::exit(1);
    }
}
