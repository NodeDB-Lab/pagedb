//! Page nonces across reopens, read as raw envelope bytes from the files.
//!
//! Each scenario seals pages and then abandons them with no durable commit. The
//! next open has only the header's anchor to start from.

use std::ops::Range;
use std::sync::atomic::Ordering;

use crate::crypto::nonce::MAX_ANCHOR_BUDGET;
use crate::options::OpenOptions;
use crate::pager::PageKind;
use crate::pager::format::data_page::ENVELOPE_OVERHEAD;
use crate::pager::page_nonce_ledger::{PageNonceLedger, read_image};
use crate::txn::db::core::RekeyTestFault;
use crate::vfs::Vfs;
use crate::vfs::gated::GatedVfs;
use crate::vfs::memory::MemVfs;
use crate::{Db, PagedbError, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x51; 32];
const REALM: RealmId = RealmId::new([0x62; 16]);
const MAIN: &str = "/main.db";
const SCRATCH: &str = "/main.db.rekey";
const BUDGET: u64 = 8;
/// Wide enough that a run of [`LARGE_RUN_PAGES`] pages needs no anchor refresh.
const LARGE_BUDGET: u64 = 4096;
const LARGE_RUN_PAGES: u64 = 32;

fn options(budget: u64) -> OpenOptions {
    OpenOptions::default().with_anchor_budget(budget)
}

async fn create<V: Vfs + Clone>(vfs: &V, budget: u64) -> Db<V> {
    let db = Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, options(budget))
        .await
        .unwrap();
    let mut write = db.begin_write().await.unwrap();
    write.put(b"seed", b"value").await.unwrap();
    write.commit().await.unwrap();
    db
}

async fn reopen<V: Vfs + Clone>(vfs: &V, budget: u64) -> Db<V> {
    Db::open_existing_with_options(vfs.clone(), KEK, PAGE, REALM, options(budget))
        .await
        .unwrap()
}

/// Seal one page of `fill` at each id in `pages`. No commit follows.
async fn flush_uncommitted_pages<V: Vfs + Clone>(db: &Db<V>, pages: Range<u64>, fill: u8) {
    let body = vec![fill; PAGE - ENVELOPE_OVERHEAD];
    for page_id in pages {
        db.pager
            .write_main_page(page_id, REALM, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
    }
    db.pager.flush_main(REALM).await.unwrap();
}

async fn next_page_id<V: Vfs + Clone>(db: &Db<V>) -> u64 {
    db.writer.lock().await.next_page_id
}

#[tokio::test(flavor = "current_thread")]
async fn page_nonces_stay_distinct_across_reopens_with_no_commit() {
    let vfs = MemVfs::new();
    drop(create(&vfs, BUDGET).await);
    let mut ledger = PageNonceLedger::default();
    ledger.record_file(&vfs, MAIN, PAGE).await;

    for round in 0..3u8 {
        let db = reopen(&vfs, BUDGET).await;
        let page_id = next_page_id(&db).await;
        flush_uncommitted_pages(&db, page_id..page_id + 1, 0x40 + round).await;
        ledger.record_file(&vfs, MAIN, PAGE).await;
    }

    ledger.assert_page_nonces_are_distinct("reopen loop");
}

#[tokio::test(flavor = "current_thread")]
async fn first_flush_after_open_persists_the_anchor_before_sealing() {
    let vfs = MemVfs::new();
    drop(create(&vfs, BUDGET).await);

    let db = reopen(&vfs, BUDGET).await;
    let anchor = db.pager.durable_anchor();
    let seq = db.pager.header_cursor().unwrap().seq;
    assert_eq!(db.pager.main_anchor_window(), 0);

    let page_id = next_page_id(&db).await;
    flush_uncommitted_pages(&db, page_id..page_id + 1, 0x11).await;

    assert_eq!(db.pager.durable_anchor(), anchor + MAX_ANCHOR_BUDGET);
    assert_eq!(db.pager.header_cursor().unwrap().seq, seq + 1);
    drop(db);

    let again = reopen(&vfs, BUDGET).await;
    assert_eq!(
        again.pager.durable_anchor(),
        anchor + MAX_ANCHOR_BUDGET,
        "the header must hold the anchor the flush persisted"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_first_refresh_returns_an_error_and_seals_nothing() {
    let vfs = GatedVfs::new();
    drop(create(&vfs, BUDGET).await);

    let db = reopen(&vfs, BUDGET).await;
    let anchor = db.pager.durable_anchor();
    let page_id = next_page_id(&db).await;
    let body = vec![0x22; PAGE - ENVELOPE_OVERHEAD];
    db.pager
        .write_main_page(page_id, REALM, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();
    let image = read_image(&vfs, MAIN).await;
    let slot = db.pager.header_cursor().unwrap().slot;
    vfs.fail_next_write_at(MAIN, slot.other().page_id() * PAGE as u64);

    let error = db.pager.flush_main(REALM).await.unwrap_err();

    assert!(matches!(error, PagedbError::Io(_)), "got {error:?}");
    assert_eq!(db.pager.durable_anchor(), anchor);
    assert!(
        read_image(&vfs, MAIN).await == image,
        "a failed refresh must leave the file as it was"
    );
    db.pager.discard_dirty_main();
}

/// The public path. The first header write of each run is the refresh, and the
/// VFS refuses it, so a commit fails before it seals a page.
#[tokio::test(flavor = "current_thread")]
async fn a_commit_refused_at_the_refresh_seals_no_page() {
    let vfs = GatedVfs::new();
    drop(create(&vfs, BUDGET).await);
    let mut ledger = PageNonceLedger::default();
    ledger.record_file(&vfs, MAIN, PAGE).await;

    for round in 0..3u8 {
        let db = reopen(&vfs, BUDGET).await;
        let mut write = db.begin_write().await.unwrap();
        write.put(b"round", &[round; 64]).await.unwrap();
        let image = read_image(&vfs, MAIN).await;
        let slot = db.pager.header_cursor().unwrap().slot;
        vfs.fail_next_write_at(MAIN, slot.other().page_id() * PAGE as u64);

        let error = write.commit().await.unwrap_err();

        assert!(matches!(error, PagedbError::Io(_)), "got {error:?}");
        assert!(
            read_image(&vfs, MAIN).await == image,
            "round {round}: a refused refresh must leave the file as it was"
        );
        db.ensure_usable().unwrap();
        ledger.record_file(&vfs, MAIN, PAGE).await;
    }

    ledger.assert_page_nonces_are_distinct("commit refused at the refresh");
}

/// The public path. The refresh lands and the commit's own header does not, so
/// each run leaves sealed pages that no header names.
#[tokio::test(flavor = "current_thread")]
async fn page_nonces_stay_distinct_when_each_commit_header_is_refused() {
    let vfs = GatedVfs::new();
    let seeded = create(&vfs, BUDGET).await;
    let base = seeded.latest_commit();
    drop(seeded);
    let mut ledger = PageNonceLedger::default();
    ledger.record_file(&vfs, MAIN, PAGE).await;

    for round in 0..3u8 {
        let db = reopen(&vfs, BUDGET).await;
        let mut write = db.begin_write().await.unwrap();
        write.put(b"round", &[round; 64]).await.unwrap();
        // The refresh takes the other slot, so the commit's header lands here.
        let slot = db.pager.header_cursor().unwrap().slot;
        vfs.fail_next_write_at(MAIN, slot.page_id() * PAGE as u64);

        assert!(write.commit().await.is_err(), "round {round}");
        ledger.record_file(&vfs, MAIN, PAGE).await;
    }

    assert_eq!(reopen(&vfs, BUDGET).await.latest_commit(), base);
    ledger.assert_page_nonces_are_distinct("commit header refused");
}

#[tokio::test(flavor = "current_thread")]
async fn page_nonces_stay_distinct_when_the_budget_shrinks() {
    let vfs = MemVfs::new();
    let mut ledger = PageNonceLedger::default();

    let db = create(&vfs, LARGE_BUDGET).await;
    let first = next_page_id(&db).await;
    let pages = first..first + LARGE_RUN_PAGES;
    flush_uncommitted_pages(&db, pages.clone(), 0x11).await;
    ledger.record_file(&vfs, MAIN, PAGE).await;
    drop(db);

    let db = reopen(&vfs, BUDGET).await;
    flush_uncommitted_pages(&db, pages, 0x22).await;
    ledger.record_file(&vfs, MAIN, PAGE).await;

    ledger.assert_page_nonces_are_distinct("budget change");
}

/// The first rebuild leaves its scratch behind. The next open removes that scratch
/// and rebuilds under the same target key, so both files count.
#[tokio::test(flavor = "current_thread")]
async fn page_nonces_stay_distinct_when_a_rebuild_restarts_after_a_crash() {
    let vfs = MemVfs::new();
    let db = create(&vfs, LARGE_BUDGET).await;
    let mut write = db.begin_write().await.unwrap();
    for row in 0..LARGE_RUN_PAGES {
        write
            .put(format!("row-{row:04}").as_bytes(), &[0x33; 3000])
            .await
            .unwrap();
    }
    write.commit().await.unwrap();

    db.interrupt_rekey_after(RekeyTestFault::MainPagesTargetReadable);
    assert!(db.rekey_db(KEK, 1).await.is_err());
    drop(db);
    let mut ledger = PageNonceLedger::default();
    ledger.record_file(&vfs, SCRATCH, PAGE).await;

    let resumed = reopen(&vfs, BUDGET).await;
    assert_eq!(resumed.mk_epoch.load(Ordering::SeqCst), 1);
    ledger.record_file(&vfs, MAIN, PAGE).await;

    ledger.assert_page_nonces_are_distinct("rebuild restart");
}
