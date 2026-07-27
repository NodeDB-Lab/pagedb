//! pagedb compaction benchmarks (fluxbench): the dense repack that rebuilds the
//! main and catalog B+ trees into a low-address layout and truncates the tail.
//!
//! Runs on `MemVfs`, so the figure is the repack's CPU + AEAD cost — full-tree
//! enumeration, bulk rebuild, header commit — not the cost of writing a repacked
//! file to a real disk.
//!
//! Run with: `cargo bench --bench compaction`

mod common;

use common::{block_on, drain_parked, park};
use fluxbench::bench;
use fluxbench::prelude::*;

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [7; 32];
const REALM: RealmId = RealmId::new([3; 16]);
const VALUE_LEN: usize = 128;
/// Enough keys to span many pages, so the repack rebuilds a multi-level tree.
const INSERTED_KEYS: u32 = 1_200;
/// Deleted to populate the free-list — an empty free-list makes `compact_now`
/// skip the repack entirely, since every page below the high-water mark is live.
const DELETED_KEYS: u32 = 1_100;

/// Untimed: build a store whose free-list is large enough to make the next
/// `compact_now` take the dense-repack path.
fn prepared_dense_repack() -> Db<MemVfs> {
    block_on(async {
        // Retire the previous iteration's store here, where it is not measured.
        drain_parked();

        let db = Db::open(MemVfs::new(), KEK, PAGE, REALM, OpenOptions::default())
            .await
            .expect("open bench store");
        let value = [0x2A; VALUE_LEN];

        let mut write = db.begin_write().await.expect("begin insert txn");
        for i in 0..INSERTED_KEYS {
            write
                .put(format!("key-{i:06}").as_bytes(), &value)
                .await
                .expect("insert");
        }
        write.commit().await.expect("commit inserts");

        let mut delete = db.begin_write().await.expect("begin delete txn");
        for i in 0..DELETED_KEYS {
            delete
                .delete(format!("key-{i:06}").as_bytes())
                .await
                .expect("delete");
        }
        delete.commit().await.expect("commit deletes");
        db
    })
}

#[bench(group = "compaction/dense_repack")]
fn dense_repack(b: &mut Bencher) {
    b.iter_with_setup(prepared_dense_repack, |db| {
        block_on(async move {
            let stats = db.compact_now().await.expect("compact");
            assert!(
                stats.main_db_pages_reclaimed > 0,
                "setup did not enter dense repack: {stats:?}"
            );
            // Teardown is not part of the operation under test.
            park(db);
            stats
        })
    });
}

fn main() {
    if let Err(error) = fluxbench::run() {
        eprintln!("fluxbench error: {error}");
        std::process::exit(1);
    }
}
