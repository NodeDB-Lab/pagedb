//! Cold-cache B+ tree traversal benchmark for authenticated node-kind
//! discovery.
//!
//! Every timed lookup descends a multi-level tree with an empty main-page
//! cache, so each internal and leaf node costs a real decrypt plus the
//! envelope/body kind agreement check in `BTree::read_node_guard`. The cache
//! eviction that creates those conditions is deliberately *outside* the timed
//! region — measuring it would charge cache bookkeeping to the read path.
//!
//! Runs on `MemVfs`: the figure is CPU + AEAD for an authenticated cold
//! descent, not the cost of reaching real storage.
//!
//! Run with: `cargo bench --bench authenticated_node_read`

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::{block_on, with_rt};
use fluxbench::bench;
use fluxbench::prelude::*;

use pagedb::options::{OpenOptions, RetainPolicy};
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};

const PAGE: usize = 4096;
const KEY_COUNT: usize = 1_000;
const REALM: RealmId = RealmId::new([0x51; 16]);
const VALUE: &[u8] = b"authenticated-node-read";

thread_local! {
    /// Built once and reused: this workload only reads, so rebuilding the tree
    /// per iteration would add setup noise without changing what is measured.
    static DB: RefCell<Option<Rc<Db<MemVfs>>>> = const { RefCell::new(None) };
}

fn key(index: usize) -> Vec<u8> {
    format!("node:{index:08}").into_bytes()
}

fn shared_db() -> Rc<Db<MemVfs>> {
    DB.with(|cell| {
        if cell.borrow().is_none() {
            let db = block_on(async {
                // Commit history is irrelevant here and would only add
                // unrelated catalog writes to the setup.
                let options =
                    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
                let db =
                    Db::open_internal_with_options(MemVfs::new(), [0xA5; 32], PAGE, REALM, options)
                        .await
                        .expect("open bench store");
                let mut write = db.begin_write().await.expect("begin txn");
                for index in 0..KEY_COUNT {
                    write.put(&key(index), VALUE).await.expect("insert");
                }
                write.commit().await.expect("commit");
                db
            });
            *cell.borrow_mut() = Some(Rc::new(db));
        }
        cell.borrow().as_ref().expect("db initialised").clone()
    })
}

#[bench(group = "pager/authenticated-node-read")]
fn cold_tree_get(b: &mut Bencher) {
    let db = shared_db();
    let mut index = 0usize;

    b.iter_with_setup(
        || {
            // Untimed: drop the warm pages and pre-build the lookup key, so the
            // timed region is descent plus authentication only.
            let lookup_key = key(index % KEY_COUNT);
            index = index.wrapping_add(1);
            db.evict_main_pages(REALM);
            lookup_key
        },
        |lookup_key| {
            with_rt(|rt| {
                rt.block_on(async {
                    let read = db.begin_read().await.expect("begin read");
                    read.get(&lookup_key).await.expect("get")
                })
            })
        },
    );
}

fn main() {
    if let Err(error) = fluxbench::run() {
        eprintln!("fluxbench error: {error}");
        std::process::exit(1);
    }
}
