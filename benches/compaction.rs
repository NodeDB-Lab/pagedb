//! PageDB dense-repack benchmark.
//!
//! Run with: `cargo bench --bench compaction`

use std::cell::RefCell;

use fluxbench::TrackingAllocator;
use fluxbench::bench;
use fluxbench::prelude::*;

use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [7; 32];
const REALM: RealmId = RealmId::new([3; 16]);
const INSERTED_KEYS: u32 = 1_200;
const DELETED_KEYS: u32 = 1_100;

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

thread_local! {
    static RT: RefCell<tokio::runtime::Runtime> = RefCell::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
    );
}

fn with_rt<R>(f: impl FnOnce(&tokio::runtime::Runtime) -> R) -> R {
    RT.with(|rt| f(&rt.borrow()))
}

fn prepared_dense_repack() -> Db<MemVfs> {
    with_rt(|rt| {
        rt.block_on(async {
            let db = Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
                .await
                .unwrap();
            let value = [0x2A; 128];
            let mut write = db.begin_write().await.unwrap();
            for i in 0..INSERTED_KEYS {
                write
                    .put(format!("key-{i:06}").as_bytes(), &value)
                    .await
                    .unwrap();
            }
            write.commit().await.unwrap();

            let mut delete = db.begin_write().await.unwrap();
            for i in 0..DELETED_KEYS {
                delete
                    .delete(format!("key-{i:06}").as_bytes())
                    .await
                    .unwrap();
            }
            delete.commit().await.unwrap();
            db
        })
    })
}

#[bench(group = "compaction/dense_repack")]
fn dense_repack(b: &mut Bencher) {
    b.iter_with_setup(prepared_dense_repack, |db| {
        with_rt(|rt| {
            rt.block_on(async move {
                let stats = db.compact_now().await.unwrap();
                assert!(stats.main_db_pages_reclaimed > 0);
                stats
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
