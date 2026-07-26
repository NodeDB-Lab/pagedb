//! Cold-cache B+ tree traversal benchmark for authenticated node-kind
//! discovery.
//!
//! Run with: `cargo bench --bench authenticated_node_read`

use std::cell::RefCell;
use std::hint::black_box;
use std::sync::Arc;

use fluxbench::prelude::*;
use fluxbench::{TrackingAllocator, bench};
use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};
use tokio::sync::Mutex as AsyncMutex;

#[global_allocator]
static GLOBAL_ALLOCATOR: TrackingAllocator = TrackingAllocator;

const PAGE: usize = 4096;
const KEY_COUNT: usize = 1_000;
const REALM: RealmId = RealmId::new([0x51; 16]);
const VALUE: &[u8] = b"authenticated-node-read";

type SharedDb = Arc<AsyncMutex<Db<MemVfs>>>;

thread_local! {
    static DB: RefCell<Option<SharedDb>> = const { RefCell::new(None) };
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
}

fn key(index: usize) -> Vec<u8> {
    format!("node:{index:08}").into_bytes()
}

fn with_runtime<R>(f: impl FnOnce(&tokio::runtime::Runtime) -> R) -> R {
    RT.with(f)
}

fn shared_db() -> SharedDb {
    DB.with(|cell| {
        if cell.borrow().is_none() {
            let db = with_runtime(|runtime| {
                runtime.block_on(async {
                    let options =
                        OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
                    let db = Db::open_internal_with_options(
                        MemVfs::new(),
                        [0xA5; 32],
                        PAGE,
                        REALM,
                        options,
                    )
                    .await
                    .unwrap();
                    let mut write = db.begin_write().await.unwrap();
                    for index in 0..KEY_COUNT {
                        write.put(&key(index), VALUE).await.unwrap();
                    }
                    write.commit().await.unwrap();
                    db
                })
            });
            *cell.borrow_mut() = Some(Arc::new(AsyncMutex::new(db)));
        }
        cell.borrow().as_ref().unwrap().clone()
    })
}

#[bench(group = "pager/authenticated-node-read")]
fn cold_tree_get(b: &mut Bencher) {
    let db = shared_db();
    let mut index = 0usize;
    b.iter(|| {
        let lookup_key = key(index % KEY_COUNT);
        index = index.wrapping_add(1);
        with_runtime(|runtime| {
            runtime.block_on(async {
                let db = db.lock().await;
                db.evict_main_pages(REALM);
                let read = db.begin_read_non_abortable().await.unwrap();
                black_box(read.get(&lookup_key).await.unwrap())
            })
        })
    });
}

fn main() {
    if let Err(error) = fluxbench::run() {
        eprintln!("fluxbench error: {error}");
        std::process::exit(1);
    }
}
