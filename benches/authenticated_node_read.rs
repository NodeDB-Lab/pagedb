//! Cold-cache B+ tree traversal benchmark for authenticated node-kind
//! discovery.
//!
//! Every timed lookup descends a multi-level tree with an empty main-page
//! cache, so each internal and leaf node costs a real decrypt plus the
//! envelope/body kind agreement check in `BTree::read_node_guard`. The store is
//! built once; each iteration opens its own handle over those same bytes, and a
//! fresh handle starts with an empty buffer pool. Opening and retiring handles
//! is deliberately *outside* the timed region — measuring it would charge
//! handle setup to the read path.
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
const KEK: [u8; 32] = [0xA5; 32];
const VALUE: &[u8] = b"authenticated-node-read";

thread_local! {
    /// The populated store's bytes, built once: this workload only reads, so
    /// rebuilding the tree per iteration would add setup noise without changing
    /// what is measured.
    static STORE: RefCell<Option<MemVfs>> = const { RefCell::new(None) };
}

fn key(index: usize) -> Vec<u8> {
    format!("node:{index:08}").into_bytes()
}

fn populated_store() -> MemVfs {
    STORE.with(|cell| {
        if cell.borrow().is_none() {
            let vfs = MemVfs::new();
            block_on(async {
                // Commit history is irrelevant here and would only add
                // unrelated catalog writes to the setup.
                let options =
                    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled);
                let db = Db::open(vfs.clone(), KEK, PAGE, REALM, options)
                    .await
                    .expect("open bench store");
                let mut write = db.begin_write().await.expect("begin txn");
                for index in 0..KEY_COUNT {
                    write.put(&key(index), VALUE).await.expect("insert");
                }
                write.commit().await.expect("commit");
                // The writer handle drops with this block, releasing its
                // sentinel so the read-only handles below can attach.
            });
            *cell.borrow_mut() = Some(vfs);
        }
        cell.borrow().as_ref().expect("store initialised").clone()
    })
}

/// A handle whose buffer pool is empty, over an already-populated store.
fn cold_handle(store: &MemVfs) -> Db<MemVfs> {
    block_on(async {
        Db::open_read_only(store.clone(), KEK, PAGE, REALM, OpenOptions::default())
            .await
            .expect("open cold read-only handle")
    })
}

#[bench(group = "pager/authenticated-node-read")]
fn cold_tree_get(b: &mut Bencher) {
    let store = populated_store();
    // `Rc` so the timed region can lift the handle out of the cell *before* it
    // awaits: a `RefCell` borrow held across an await point is what
    // `clippy::await_holding_refcell_ref` rejects, and cloning the `Rc` costs a
    // refcount bump rather than moving the handle's teardown into the
    // measurement.
    let handle: RefCell<Option<Rc<Db<MemVfs>>>> = RefCell::new(None);
    let mut index = 0usize;

    b.iter_with_setup(
        || {
            // Untimed: retire the previous iteration's warm handle, open a cold
            // one, and pre-build the lookup key, so the timed region is descent
            // plus authentication only.
            let lookup_key = key(index % KEY_COUNT);
            index = index.wrapping_add(1);
            handle.borrow_mut().take();
            *handle.borrow_mut() = Some(Rc::new(cold_handle(&store)));
            lookup_key
        },
        |lookup_key| {
            with_rt(|rt| {
                rt.block_on(async {
                    let db = handle
                        .borrow()
                        .as_ref()
                        .map(Rc::clone)
                        .expect("handle opened in setup");
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
