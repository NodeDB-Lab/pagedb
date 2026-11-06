//! The rebuild keeps the only copy of a live page out of harm's way, and leaves
//! no page under the source key.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use crate::btree::BTree;
use crate::catalog::codec::{RekeyIntent, RekeyStage};
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::options::RetainPolicy;
use crate::pager::PageKind;
use crate::pager::format::data_page::body_capacity;
use crate::recovery::deep_walk::run_deep_walk;
use crate::txn::db::core::RekeyTestFault;
use crate::txn::db::rekey::intent::intent_proof;
use crate::vfs::gated::{GatedVfs, bounded};
use crate::vfs::memory::MemVfs;
use crate::vfs::{OpenMode, Vfs, VfsFile};
use crate::{Db, OpenOptions, PagedbError, Result};

use super::{KEK0, PAGE, REALM};

const NEW_KEK: [u8; 32] = [0xAB; 32];
const SCRATCH: &str = "/main.db.rekey";
const ROWS: u32 = 60;
/// A value past the inline threshold that fits in one overflow page.
const VALUE_LEN: usize = 3000;
/// A small pool, so a rebuild flushes to its scratch many times.
const POOL_PAGES: usize = 16;

/// How the rekey under test changes keys. A reopen needs both keys when the KEK
/// changes, and one when it stays.
#[derive(Clone, Copy, Debug)]
enum KeyCase {
    SameKek,
    NewKek,
}

const KEY_CASES: [KeyCase; 2] = [KeyCase::SameKek, KeyCase::NewKek];

impl KeyCase {
    fn target_kek(self) -> [u8; 32] {
        match self {
            Self::SameKek => KEK0,
            Self::NewKek => NEW_KEK,
        }
    }

    /// Reopen holding the source key, plus the target key when they differ.
    async fn reopen<V: Vfs + Clone>(self, vfs: V) -> Result<Db<V>> {
        match self {
            Self::SameKek => Db::open_existing(vfs, KEK0, PAGE, REALM).await,
            Self::NewKek => {
                Db::open_existing_with_counterpart_kek(
                    vfs,
                    KEK0,
                    NEW_KEK,
                    PAGE,
                    REALM,
                    OpenOptions::default(),
                )
                .await
            }
        }
    }
}

fn small_pool() -> OpenOptions {
    OpenOptions::default().with_buffer_pool_pages(POOL_PAGES)
}

fn no_history() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)
}

fn row_key(row: u32) -> Vec<u8> {
    format!("row-{row:05}").into_bytes()
}

fn row_value(row: u32, generation: u8) -> Vec<u8> {
    let mut value = vec![generation; VALUE_LEN];
    value[..4].copy_from_slice(&row.to_le_bytes());
    value
}

async fn write_rows<V: Vfs + Clone>(db: &Db<V>, generation: u8) -> crate::CommitId {
    let mut txn = db.begin_write().await.unwrap();
    for row in 0..ROWS {
        txn.put(&row_key(row), &row_value(row, generation))
            .await
            .unwrap();
    }
    txn.commit().await.unwrap()
}

async fn assert_rows_read<V: Vfs + Clone>(db: &Db<V>, generation: u8, label: &str) {
    let reader = db.begin_read().await.unwrap();
    for row in 0..ROWS {
        assert_eq!(
            reader.get(&row_key(row)).await.unwrap().as_deref(),
            Some(row_value(row, generation).as_slice()),
            "{label}: row {row}"
        );
    }
}

async fn assert_clean_walk<V: Vfs + Clone>(db: &Db<V>, label: &str) {
    let report = run_deep_walk(db).await.unwrap();
    assert!(report.is_clean(), "{label}: deep walk report: {report:?}");
}

async fn assert_rekey_finished<V: Vfs + Clone>(db: &Db<V>, target_epoch: u64, label: &str) {
    {
        let state = db.writer.lock().await;
        assert!(
            db.load_rekey_intent(&state).await.unwrap().is_none(),
            "{label}: the intent is gone"
        );
    }
    assert_eq!(db.mk_epoch.load(Ordering::SeqCst), target_epoch, "{label}");
    assert!(
        matches!(
            db.pager.mk_for(0, db.cipher_id),
            Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
        ),
        "{label}: the source key is gone"
    );
}

/// The bytes of a page, or `None` past the end of the file.
async fn raw_page<V: Vfs>(vfs: &V, page_id: u64) -> Option<Vec<u8>> {
    let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    let offset = page_id * PAGE as u64;
    if offset >= file.len().await.unwrap() {
        return None;
    }
    let mut page = vec![0u8; PAGE];
    let read = file.read_at(offset, &mut page).await.unwrap();
    assert_eq!(read, PAGE, "the file ends inside page {page_id}");
    Some(page)
}

/// A page's envelope names its epoch at bytes 4..12.
fn sealed_epoch(page: &[u8]) -> u64 {
    u64::from_le_bytes(page[4..12].try_into().unwrap())
}

fn is_zero(page: &[u8]) -> bool {
    page.iter().all(|&byte| byte == 0)
}

/// Every header slot and page holds zeros or names `target_epoch`.
async fn assert_every_page_at_target<V: Vfs>(vfs: &V, target_epoch: u64, label: &str) {
    let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    let pages = file.len().await.unwrap() / PAGE as u64;
    drop(file);
    for slot in 0..2 {
        let header = raw_page(vfs, slot).await.unwrap();
        if !is_zero(&header) {
            let epoch = u64::from_le_bytes(header[48..56].try_into().unwrap());
            assert_eq!(epoch, target_epoch, "{label}: header slot {slot}");
        }
    }
    for page_id in 4..pages {
        let page = raw_page(vfs, page_id).await.unwrap();
        if !is_zero(&page) {
            assert_eq!(sealed_epoch(&page), target_epoch, "{label}: page {page_id}");
        }
    }
}

/// Assert `page_id` holds zeros, lies past the file, or names `target_epoch`.
async fn assert_left_source_key<V: Vfs>(vfs: &V, page_id: u64, target_epoch: u64, label: &str) {
    if let Some(page) = raw_page(vfs, page_id).await
        && !is_zero(&page)
    {
        assert_eq!(sealed_epoch(&page), target_epoch, "{label}: page {page_id}");
    }
}

async fn seal_page_under_active_key<V: Vfs + Clone>(db: &Db<V>, page_id: u64) {
    let body = vec![0x5A; body_capacity(PAGE)];
    db.pager
        .write_main_page(page_id, REALM, PageKind::BTreeLeaf, &body)
        .await
        .unwrap();
    db.pager.flush_main(REALM).await.unwrap();
}

/// Seal a page no root and no free list names. It sits below the cursor once a
/// commit makes the moved cursor durable.
async fn seal_orphan_below_the_cursor<V: Vfs + Clone>(db: &Db<V>) -> u64 {
    let page_id = {
        let mut state = db.writer.lock().await;
        let page_id = state.next_page_id;
        state.next_page_id = page_id + 1;
        page_id
    };
    seal_page_under_active_key(db, page_id).await;
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"cursor-carrier", b"value").await.unwrap();
    txn.commit().await.unwrap();
    page_id
}

/// Seal a page past the cursor, as a crash mid-commit leaves one.
async fn seal_orphan_past_the_cursor<V: Vfs + Clone>(db: &Db<V>) -> u64 {
    let page_id = db.writer.lock().await.next_page_id + 50;
    seal_page_under_active_key(db, page_id).await;
    page_id
}

async fn live_node_pages<V: Vfs + Clone>(db: &Db<V>) -> Vec<(u64, PageKind)> {
    let (root, next) = {
        let state = db.writer.lock().await;
        (state.root_page_id, state.next_page_id)
    };
    let mut reachable = BTreeSet::new();
    BTree::open(db.pager.clone(), REALM, root, next, PAGE)
        .collect_all_page_ids(&mut reachable)
        .await
        .unwrap();
    let mut nodes = Vec::new();
    for page_id in reachable {
        if let Ok((_, kind)) = db.pager.read_main_node(page_id, REALM).await {
            nodes.push((page_id, kind));
        }
    }
    nodes
}

/// The stop comes with every named page in the scratch. The live pages keep every
/// byte, and a tear lands in the scratch, which holds no only copy of anything.
#[tokio::test(flavor = "current_thread")]
async fn a_stop_before_the_rename_leaves_live_page_bytes_unchanged_and_a_torn_scratch_costs_nothing()
 {
    for case in KEY_CASES {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
            .await
            .unwrap();
        write_rows(&db, 1).await;
        let (leaf, _) = live_node_pages(&db)
            .await
            .into_iter()
            .find(|&(_, kind)| kind == PageKind::BTreeLeaf)
            .expect("setup error: the tree holds no leaf");
        let pages_before = {
            let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
            file.len().await.unwrap() / PAGE as u64
        };
        let mut live_before = Vec::new();
        for page_id in 4..pages_before {
            live_before.push(raw_page(&vfs, page_id).await.unwrap());
        }

        db.interrupt_rekey_after(RekeyTestFault::MainPagesTargetReadable);
        assert!(db.rekey_db(case.target_kek(), 1).await.is_err(), "{case:?}");
        drop(db);

        for (page_id, page) in (4..pages_before).zip(&live_before) {
            assert_eq!(
                &raw_page(&vfs, page_id).await.unwrap(),
                page,
                "{case:?}: page {page_id}"
            );
        }
        let mut scratch = vfs.open(SCRATCH, OpenMode::ReadWrite).await.unwrap();
        scratch
            .write_at(leaf * PAGE as u64 + (PAGE / 2) as u64, &[0xEE; PAGE / 2])
            .await
            .unwrap();
        scratch.sync().await.unwrap();
        drop(scratch);

        let reopened = case
            .reopen(vfs.clone())
            .await
            .unwrap_or_else(|error| panic!("{case:?}: the open failed: {error:?}"));
        assert_rows_read(&reopened, 1, "after the tear").await;
        assert_rekey_finished(&reopened, 1, "after the tear").await;
        assert_clean_walk(&reopened, "after the tear").await;
    }
}

/// Stop at every write to the scratch, in both key cases. The source key alone or
/// with its counterpart reads all data, and the store finishes the rekey.
#[tokio::test(flavor = "current_thread")]
async fn a_crash_at_any_rebuild_write_reopens_with_all_data_under_both_key_cases() {
    for case in KEY_CASES {
        let mut stopped_at = 0;
        loop {
            let vfs = GatedVfs::new();
            let db = Db::open(vfs.clone(), KEK0, PAGE, REALM, small_pool())
                .await
                .unwrap();
            write_rows(&db, 0).await;
            write_rows(&db, 1).await;

            let gate = vfs.park_write_number(SCRATCH, stopped_at);
            let mut rekey = Box::pin(db.rekey_db(case.target_kek(), 1));
            let finished = bounded(async {
                tokio::select! {
                    biased;
                    () = gate.wait_until_parked() => false,
                    outcome = &mut rekey => {
                        outcome.unwrap();
                        true
                    }
                }
            })
            .await;
            drop(rekey);
            drop(db);
            if finished {
                assert!(
                    stopped_at > 2,
                    "{case:?}: the rebuild made only {stopped_at} writes"
                );
                break;
            }

            let label = format!("{case:?} stopped at write {stopped_at}");
            let reopened = case
                .reopen(vfs.clone())
                .await
                .unwrap_or_else(|error| panic!("{label}: the open failed: {error:?}"));
            assert_rows_read(&reopened, 1, &label).await;
            assert_rekey_finished(&reopened, 1, &label).await;
            assert!(
                vfs.open(SCRATCH, OpenMode::Read).await.is_err(),
                "{label}: the scratch stayed"
            );
            assert_every_page_at_target(&vfs, 1, &label).await;
            assert_clean_walk(&reopened, &label).await;
            stopped_at += 1;
        }
    }
}

/// A crash leaves its scratch behind. The next open removes it and starts over.
#[tokio::test(flavor = "current_thread")]
async fn a_scratch_left_by_a_crash_is_removed_and_the_rekey_starts_over() {
    for point in [
        RekeyTestFault::MainPagesTargetReadable,
        RekeyTestFault::HeaderTargetPublished,
    ] {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
            .await
            .unwrap();
        write_rows(&db, 1).await;
        db.interrupt_rekey_after(point);
        assert!(db.rekey_db(KEK0, 1).await.is_err(), "{point:?}");
        drop(db);
        assert!(
            vfs.open(SCRATCH, OpenMode::Read).await.is_ok(),
            "{point:?}: setup error: no scratch stayed"
        );

        let reopened = Db::open_existing(vfs.clone(), KEK0, PAGE, REALM)
            .await
            .unwrap();
        assert!(
            vfs.open(SCRATCH, OpenMode::Read).await.is_err(),
            "{point:?}"
        );
        assert_rows_read(&reopened, 1, "after the restart").await;
        assert_rekey_finished(&reopened, 1, "after the restart").await;
    }
}

/// An orphan holds whatever a crash or a leak left, under the source key. It must
/// not outlive a rekey done to rotate that key away.
#[tokio::test(flavor = "current_thread")]
async fn unnamed_pages_below_and_past_the_cursor_leave_the_source_key() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    write_rows(&db, 1).await;
    let below = seal_orphan_below_the_cursor(&db).await;
    let past = seal_orphan_past_the_cursor(&db).await;
    for page_id in [below, past] {
        let page = raw_page(&vfs, page_id).await.unwrap();
        assert_eq!(sealed_epoch(&page), 0, "setup error: page {page_id}");
    }

    db.rekey_db(KEK0, 1).await.unwrap();

    assert!(
        is_zero(&raw_page(&vfs, below).await.unwrap()),
        "page {below}"
    );
    assert_left_source_key(&vfs, past, 1, "past the cursor").await;
    assert_every_page_at_target(&vfs, 1, "after the rekey").await;
    let cursor = db.writer.lock().await.next_page_id;
    let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    assert!(
        file.len().await.unwrap() <= cursor * PAGE as u64,
        "the file ends at the cursor"
    );
    drop(file);
    assert_rows_read(&db, 1, "after the rekey").await;
    assert_clean_walk(&db, "after the rekey").await;
    drop(db);

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    assert_rows_read(&reopened, 1, "after the reopen").await;
    assert_clean_walk(&reopened, "after the reopen").await;
}

/// The sweep covers free pages, chain pages, retained rows, and an orphan.
#[tokio::test(flavor = "current_thread")]
async fn after_a_rekey_every_page_is_zero_or_at_the_target_epoch() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    write_rows(&db, 0).await;
    write_rows(&db, 1).await;
    seal_orphan_below_the_cursor(&db).await;

    db.rekey_db(KEK0, 1).await.unwrap();

    assert_every_page_at_target(&vfs, 1, "the first rekey").await;
    assert_clean_walk(&db, "the first rekey").await;

    db.rekey_db(KEK0, 2).await.unwrap();

    assert_every_page_at_target(&vfs, 2, "the second rekey").await;
    assert_clean_walk(&db, "the second rekey").await;
}

/// The reader's pages live only on the free list, under no retained row. Its page
/// ids and their content are the same in the new file.
#[tokio::test(flavor = "current_thread")]
async fn a_reader_opened_before_the_rekey_reads_every_row_after_it() {
    let vfs = MemVfs::new();
    let db = Db::open_internal_with_options(vfs.clone(), KEK0, PAGE, REALM, no_history())
        .await
        .unwrap();
    write_rows(&db, 0).await;
    let reader = db.begin_read().await.unwrap();
    write_rows(&db, 1).await;

    db.rekey_db(KEK0, 1).await.unwrap();
    db.evict_main_pages().unwrap();

    assert!(
        db.pager.mk_for(0, db.cipher_id).is_ok(),
        "the keyring keeps the source key while the reader exists"
    );
    for row in 0..ROWS {
        assert_eq!(
            reader.get(&row_key(row)).await.unwrap().as_deref(),
            Some(row_value(row, 0).as_slice()),
            "row {row}"
        );
    }
    assert_rows_read(&db, 1, "a reader admitted after the rekey").await;
    drop(reader);
    assert_rekey_finished(&db, 1, "after the reader left").await;
    assert_every_page_at_target(&vfs, 1, "after the reader left").await;
    assert_clean_walk(&db, "after the reader left").await;
}

/// A page guard holds its own plaintext, and the cache reset spares a pinned entry.
#[tokio::test(flavor = "current_thread")]
async fn a_page_guard_held_across_the_rekey_keeps_its_plaintext() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    write_rows(&db, 1).await;
    let root = db.writer.lock().await.root_page_id;
    let (guard, _) = db.pager.read_main_node(root, REALM).await.unwrap();
    let before = guard.body_ref().to_vec();

    db.rekey_db(KEK0, 1).await.unwrap();

    assert_eq!(guard.body_ref(), before.as_slice());
    drop(guard);
    db.evict_main_pages().unwrap();
    let (reread, _) = db.pager.read_main_node(root, REALM).await.unwrap();
    assert_eq!(reread.body_ref(), before.as_slice());
    drop(reread);
    assert_clean_walk(&db, "after the guard left").await;
}

#[tokio::test(flavor = "current_thread")]
async fn retained_rows_read_their_values_across_the_rebuild() {
    let vfs = MemVfs::new();
    let options = OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded);
    let db = Db::open_internal_with_options(vfs.clone(), KEK0, PAGE, REALM, options.clone())
        .await
        .unwrap();
    let mut commits = Vec::new();
    for generation in 0..4u8 {
        commits.push((write_rows(&db, generation).await, generation));
    }
    seal_orphan_below_the_cursor(&db).await;

    db.rekey_db(KEK0, 1).await.unwrap();
    drop(db);

    let reopened = Db::open_existing_with_options(vfs.clone(), KEK0, PAGE, REALM, options)
        .await
        .unwrap();
    for (commit, generation) in commits {
        let reader = reopened.begin_read_at(commit).await.unwrap();
        for row in [0, ROWS - 1] {
            assert_eq!(
                reader.get(&row_key(row)).await.unwrap().as_deref(),
                Some(row_value(row, generation).as_slice()),
                "{commit:?} row {row}"
            );
        }
    }
    assert_every_page_at_target(&vfs, 1, "after the reopen").await;
    assert_clean_walk(&reopened, "after the reopen").await;
}

fn old_style_intent(
    db: &Db<MemVfs>,
    stage: RekeyStage,
    case: KeyCase,
) -> (RekeyIntent, crate::crypto::DerivedKey) {
    let cipher_id = db.cipher_id.as_byte();
    let source_key = derive_hk(&derive_mk(&KEK0, &db.kek_salt, 0).unwrap()).unwrap();
    let target_key = derive_hk(&derive_mk(&case.target_kek(), &db.kek_salt, 1).unwrap()).unwrap();
    let proof = |key: &crate::crypto::DerivedKey, epoch: u64| {
        intent_proof(key, &db.file_id, &db.kek_salt, 0, 1, epoch, cipher_id).unwrap()
    };
    let intent = RekeyIntent {
        source_mk_epoch: 0,
        target_mk_epoch: 1,
        source_cipher_id: cipher_id,
        target_cipher_id: cipher_id,
        same_kek: matches!(case, KeyCase::SameKek),
        stage,
        source_hk_proof: proof(&source_key, 0),
        target_hk_proof: proof(&target_key, 1),
    };
    (intent, target_key)
}

/// Every page the data and catalog trees reach, with its kind.
async fn tree_pages(db: &Db<MemVfs>) -> std::collections::BTreeMap<u64, PageKind> {
    let (roots, next) = {
        let state = db.writer.lock().await;
        (
            [state.root_page_id, state.catalog_root_page_id],
            state.next_page_id,
        )
    };
    let mut pages = std::collections::BTreeMap::new();
    for root in roots {
        BTree::open(db.pager.clone(), REALM, root, next, PAGE)
            .verify_walk_unique(&mut pages)
            .await
            .unwrap();
    }
    pages
}

async fn reseal_in_place(db: &Db<MemVfs>, page_id: u64, kind: PageKind) {
    let guard = db.pager.read_main_page(page_id, REALM, kind).await.unwrap();
    let body = guard.body_ref().to_vec();
    drop(guard);
    db.pager
        .write_main_page(page_id, REALM, kind, &body)
        .await
        .unwrap();
}

/// Reseal every free-list chain page and every page it names, as an earlier
/// release did before it wrote `MainDone`.
async fn reseal_free_list_in_place(db: &Db<MemVfs>, vfs: &MemVfs) {
    let head = db.writer.lock().await.free_list_root_page_id;
    let (entries, chain_pages) = crate::pager::freelist::read_chain(&db.pager, REALM, head)
        .await
        .unwrap();
    for page_id in chain_pages {
        reseal_in_place(db, page_id, PageKind::Free).await;
    }
    for (_, page_id) in entries {
        let raw = raw_page(vfs, page_id).await.unwrap();
        if !is_zero(&raw) {
            reseal_in_place(db, page_id, PageKind::from_byte(raw[1]).unwrap()).await;
        }
    }
}

const OLD_STYLE_COUNTER: &str = "old-style-counter";
const OLD_STYLE_SEGMENT: &str = "old-style-segment";

struct OldStyleStore {
    vfs: MemVfs,
    resealed_leaf: u64,
    orphan: u64,
}

/// What an earlier release left at `stage`. Before `HeaderTargetPublished` it holds
/// a source header and a source catalog, with every other data page under the
/// target key. At `HeaderTargetPublished` the header and the intent's catalog path
/// are under the target key too. At `MainDone` every named page is. An orphan stays
/// under the source key throughout, which is how those releases left it.
async fn store_with_old_style_intent(stage: RekeyStage, case: KeyCase) -> OldStyleStore {
    let vfs = MemVfs::new();
    let db = Db::open_internal_with_options(vfs.clone(), KEK0, PAGE, REALM, no_history())
        .await
        .unwrap();
    write_rows(&db, 0).await;
    write_rows(&db, 1).await;
    let mut segment = db
        .create_segment(REALM, crate::SegmentKind::Unspecified)
        .await
        .unwrap();
    segment
        .append_page(crate::SegmentPageKind::Data, b"old-style-page")
        .await
        .unwrap();
    let segment = segment.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment(OLD_STYLE_SEGMENT, &segment).await.unwrap();
    let mut counter = txn.counter(OLD_STYLE_COUNTER).unwrap();
    counter.set(7).await.unwrap();
    drop(counter);
    txn.commit().await.unwrap();
    let orphan = seal_orphan_below_the_cursor(&db).await;

    let source_key = db.hk.read().clone();
    let source_stage = if matches!(stage, RekeyStage::MainPagesTargetReadable) {
        stage
    } else {
        RekeyStage::Intent
    };
    let (first_intent, _) = old_style_intent(&db, source_stage, case);
    {
        let mut state = db.writer.lock().await;
        db.write_rekey_intent_locked(&mut state, &first_intent, 0, &source_key)
            .await
            .unwrap();
    }

    // The earlier in-place path: a target flush epoch behind a source header.
    let target_mk = derive_mk(&case.target_kek(), &db.kek_salt, 1).unwrap();
    db.pager.set_active_mk_epoch(target_mk, 1);
    let catalog_root = db.writer.lock().await.catalog_root_page_id;
    let catalog_pages = {
        let next = db.writer.lock().await.next_page_id;
        let mut pages = std::collections::BTreeMap::new();
        BTree::open(db.pager.clone(), REALM, catalog_root, next, PAGE)
            .verify_walk_unique(&mut pages)
            .await
            .unwrap();
        pages
    };
    let all_sealed = matches!(stage, RekeyStage::MainDone);
    let mut resealed_leaf = None;
    for (index, (page_id, kind)) in tree_pages(&db).await.into_iter().enumerate() {
        let in_catalog = catalog_pages.contains_key(&page_id);
        let first_leaf = kind == PageKind::BTreeLeaf && resealed_leaf.is_none();
        if all_sealed || (!in_catalog && (index % 2 == 0 || first_leaf)) {
            reseal_in_place(&db, page_id, kind).await;
            if kind == PageKind::BTreeLeaf && !in_catalog {
                resealed_leaf = Some(page_id);
            }
        }
    }
    if all_sealed {
        reseal_free_list_in_place(&db, &vfs).await;
    }
    db.pager.flush_main(REALM).await.unwrap();

    if matches!(
        stage,
        RekeyStage::HeaderTargetPublished | RekeyStage::MainDone
    ) {
        let (intent, target_key) = old_style_intent(&db, stage, case);
        let mut state = db.writer.lock().await;
        db.write_rekey_intent_locked(&mut state, &intent, 1, &target_key)
            .await
            .unwrap();
    }
    let resealed_leaf = resealed_leaf.expect("setup error: no leaf went under the target key");
    let raw = raw_page(&vfs, resealed_leaf).await.unwrap();
    assert_eq!(sealed_epoch(&raw), 1, "setup error: page {resealed_leaf}");
    let raw = raw_page(&vfs, orphan).await.unwrap();
    assert_eq!(sealed_epoch(&raw), 0, "setup error: page {orphan}");
    drop(db);
    OldStyleStore {
        vfs,
        resealed_leaf,
        orphan,
    }
}

/// Rows, the counter in the catalog, and the segment the catalog names.
async fn assert_old_style_data_reads(db: &Db<MemVfs>, label: &str) {
    assert_rows_read(db, 1, label).await;
    let mut txn = db.begin_write().await.unwrap();
    let counter = txn.counter(OLD_STYLE_COUNTER).unwrap();
    assert_eq!(counter.get().await.unwrap(), 7, "{label}");
    drop(counter);
    txn.abort().await;
    let segment = db.open_segment(REALM, OLD_STYLE_SEGMENT).await.unwrap();
    assert!(
        segment
            .read_page(1)
            .await
            .unwrap()
            .starts_with(b"old-style-page"),
        "{label}"
    );
    assert_eq!(segment.meta().mk_epoch, 1, "{label}");
}

#[tokio::test(flavor = "current_thread")]
async fn an_old_style_intent_with_mixed_epochs_resumes_through_a_rebuild() {
    let stages = [
        RekeyStage::Intent,
        RekeyStage::MainPagesTargetReadable,
        RekeyStage::HeaderTargetPublished,
    ];
    for case in KEY_CASES {
        for stage in stages {
            let label = format!("{case:?} {stage:?}");
            let store = store_with_old_style_intent(stage, case).await;

            let reopened = case
                .reopen(store.vfs.clone())
                .await
                .unwrap_or_else(|error| panic!("{label}: the resume failed: {error:?}"));

            assert_old_style_data_reads(&reopened, &label).await;
            assert_rekey_finished(&reopened, 1, &label).await;
            assert!(
                is_zero(&raw_page(&store.vfs, store.orphan).await.unwrap()),
                "{label}"
            );
            assert_every_page_at_target(&store.vfs, 1, &label).await;
            assert_clean_walk(&reopened, &label).await;
        }
    }
}

/// An intent at `MainDone` skips the rebuild, because the code cannot tell an
/// earlier release's file from this build's. So that release's orphan stays under
/// the source key until the next rekey, whose rebuild drops it.
#[tokio::test(flavor = "current_thread")]
async fn an_old_style_intent_at_main_done_finishes_without_a_rebuild_and_the_next_rekey_drops_its_orphan()
 {
    for case in KEY_CASES {
        let label = format!("{case:?}");
        let store = store_with_old_style_intent(RekeyStage::MainDone, case).await;

        let reopened = case
            .reopen(store.vfs.clone())
            .await
            .unwrap_or_else(|error| panic!("{label}: the resume failed: {error:?}"));

        assert_old_style_data_reads(&reopened, &label).await;
        assert_rekey_finished(&reopened, 1, &label).await;
        let raw = raw_page(&store.vfs, store.orphan).await.unwrap();
        assert_eq!(sealed_epoch(&raw), 0, "{label}: the stated limit moved");

        reopened.rekey_db(case.target_kek(), 2).await.unwrap();
        assert!(
            is_zero(&raw_page(&store.vfs, store.orphan).await.unwrap()),
            "{label}"
        );
        assert_every_page_at_target(&store.vfs, 2, &label).await;
        assert_clean_walk(&reopened, &label).await;
    }
}

/// A target page in the file means only the target key opens it, so the source key
/// alone still refuses.
#[tokio::test(flavor = "current_thread")]
async fn the_source_key_alone_refuses_an_intent_with_a_page_under_the_target_key() {
    let store = store_with_old_style_intent(RekeyStage::Intent, KeyCase::NewKek).await;
    let header_before = raw_page(&store.vfs, 0).await.unwrap();

    let error = Db::open_existing(store.vfs.clone(), KEK0, PAGE, REALM)
        .await
        .map(drop)
        .unwrap_err();

    assert!(
        matches!(error, PagedbError::RekeyResumeKeyRequired { .. }),
        "got {error:?}"
    );
    assert_eq!(raw_page(&store.vfs, 0).await.unwrap(), header_before);
}

/// No key opens a page an earlier release tore in place. The open reports the
/// damage by type and changes nothing, as it did before the rebuild existed.
#[tokio::test(flavor = "current_thread")]
async fn a_live_page_an_older_release_tore_fails_the_open_with_a_typed_error() {
    let store = store_with_old_style_intent(RekeyStage::Intent, KeyCase::SameKek).await;
    let (vfs, leaf) = (store.vfs, store.resealed_leaf);
    let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    file.write_at(leaf * PAGE as u64 + (PAGE / 2) as u64, &[0xEE; PAGE / 2])
        .await
        .unwrap();
    file.sync().await.unwrap();
    drop(file);
    let torn = raw_page(&vfs, leaf).await.unwrap();

    let error = Db::open_existing(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .map(drop)
        .unwrap_err();

    assert!(matches!(error, PagedbError::Corruption(_)), "got {error:?}");
    assert_eq!(raw_page(&vfs, leaf).await.unwrap(), torn);
}

/// The withdrawn intent means the next open needs no room for a rebuild, and a key
/// change needs no counterpart.
#[tokio::test(flavor = "current_thread")]
async fn a_rekey_out_of_disk_space_leaves_the_store_unchanged_and_openable() {
    for case in KEY_CASES {
        let vfs = GatedVfs::new();
        let db = Db::open(vfs.clone(), KEK0, PAGE, REALM, OpenOptions::default())
            .await
            .unwrap();
        write_rows(&db, 1).await;

        vfs.fail_next_write_with_no_space(SCRATCH);
        let error = db.rekey_db(case.target_kek(), 1).await.unwrap_err();

        assert!(
            matches!(
                error,
                PagedbError::RekeyNoSpace {
                    source_epoch: 0,
                    target_epoch: 1
                }
            ),
            "{case:?}: got {error:?}"
        );
        assert!(error.to_string().contains("free disk space"), "{error}");
        db.ensure_usable().unwrap();
        assert_eq!(db.mk_epoch.load(Ordering::SeqCst), 0);
        assert!(db.pager.mk_for(1, db.cipher_id).is_err(), "{case:?}");
        {
            let state = db.writer.lock().await;
            assert!(db.load_rekey_intent(&state).await.unwrap().is_none());
        }
        assert!(vfs.open(SCRATCH, OpenMode::Read).await.is_err(), "{case:?}");
        assert_rows_read(&db, 1, "after the refusal").await;
        write_rows(&db, 2).await;
        drop(db);

        let reopened = Db::open_existing(vfs.clone(), KEK0, PAGE, REALM)
            .await
            .unwrap_or_else(|error| panic!("{case:?}: the open failed: {error:?}"));
        assert_eq!(reopened.mk_epoch.load(Ordering::SeqCst), 0);
        assert_rows_read(&reopened, 2, "after the reopen").await;
        reopened.rekey_db(case.target_kek(), 1).await.unwrap();
        assert_rows_read(&reopened, 2, "after the retry").await;
        assert_clean_walk(&reopened, "after the retry").await;
    }
}

/// The resume cannot withdraw its intent, because an earlier release's file can
/// hold both keys. So the open fails, says what to do, and changes no page.
#[tokio::test(flavor = "current_thread")]
async fn an_open_out_of_disk_space_with_a_pending_rekey_keeps_the_store_and_names_the_remedy() {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK0, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    write_rows(&db, 1).await;
    db.interrupt_rekey_after(RekeyTestFault::Intent);
    assert!(db.rekey_db(KEK0, 1).await.is_err());
    drop(db);
    let cursor_pages = {
        let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
        file.len().await.unwrap() / PAGE as u64
    };
    let mut before = Vec::new();
    for page_id in 4..cursor_pages {
        before.push(raw_page(&vfs, page_id).await.unwrap());
    }

    vfs.fail_next_write_with_no_space(SCRATCH);
    let error = Db::open_existing(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .map(drop)
        .unwrap_err();

    assert!(
        matches!(
            error,
            PagedbError::RekeyNoSpace {
                source_epoch: 0,
                target_epoch: 1
            }
        ),
        "got {error:?}"
    );
    assert!(error.to_string().contains("free disk space"), "{error}");
    assert!(vfs.open(SCRATCH, OpenMode::Read).await.is_err());
    for (page_id, page) in (4..cursor_pages).zip(&before) {
        assert_eq!(
            &raw_page(&vfs, page_id).await.unwrap(),
            page,
            "page {page_id}"
        );
    }

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    assert_rows_read(&reopened, 1, "with space again").await;
    assert_rekey_finished(&reopened, 1, "with space again").await;
    assert_clean_walk(&reopened, "with space again").await;
}

/// A full device at the very first write refuses the rekey the same way a full
/// device in the rebuild does. Nothing is durable, so the handle stays usable.
#[tokio::test(flavor = "current_thread")]
async fn a_rekey_out_of_disk_space_at_its_first_intent_write_returns_the_typed_error_and_stays_usable()
 {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK0, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    write_rows(&db, 0).await;
    write_rows(&db, 1).await;
    let (catalog_root, free_root) = {
        let state = db.writer.lock().await;
        (state.catalog_root_page_id, state.free_list_root_page_id)
    };

    vfs.fail_next_write_with_no_space("/main.db");
    let error = db.rekey_db(KEK0, 1).await.unwrap_err();

    assert!(
        matches!(
            error,
            PagedbError::RekeyNoSpace {
                source_epoch: 0,
                target_epoch: 1
            }
        ),
        "got {error:?}"
    );
    db.ensure_usable().unwrap();
    {
        let state = db.writer.lock().await;
        assert_eq!(state.catalog_root_page_id, catalog_root);
        assert_eq!(state.free_list_root_page_id, free_root);
        assert!(db.load_rekey_intent(&state).await.unwrap().is_none());
    }
    assert_rows_read(&db, 1, "after the refusal").await;
    write_rows(&db, 2).await;
    drop(db);

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    assert_eq!(reopened.mk_epoch.load(Ordering::SeqCst), 0);
    assert_rows_read(&reopened, 2, "after the reopen").await;
    assert_clean_walk(&reopened, "after the reopen").await;
}

/// The DEK cache keys on the epoch and holds no key identity. A cipher built under
/// one key must not answer for another key at the same epoch.
#[tokio::test(flavor = "current_thread")]
async fn installing_or_retiring_an_epoch_key_evicts_the_ciphers_cached_for_that_epoch() {
    let db = Db::open_internal(MemVfs::new(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    let first = derive_mk(&NEW_KEK, &db.kek_salt, 9).unwrap();
    let second = derive_mk(&KEK0, &db.kek_salt, 9).unwrap();
    let cached = |key: &crate::crypto::MasterKey| {
        let mut lru = db.pager.dek_lru().lock();
        let before = lru.len();
        lru.get_or_derive(REALM, [0x77; 16], 9, db.cipher_id, key)
            .unwrap();
        lru.len() - before
    };

    db.pager.install_mk_epoch(first.clone(), 9, db.cipher_id);
    assert_eq!(cached(&first), 1, "setup error: the cache held this cipher");
    assert_eq!(cached(&first), 0, "setup error: the cache did not hold it");

    db.pager.install_mk_epoch(second.clone(), 9, db.cipher_id);
    assert_eq!(cached(&second), 1, "the install left the old key's cipher");

    db.pager.retire_mk_epoch(9, db.cipher_id).unwrap();
    assert_eq!(cached(&second), 1, "the retire left the epoch's cipher");
}

async fn sealed_page_segment<V: Vfs + Clone>(db: &Db<V>, bytes: &[u8]) -> crate::SegmentMeta {
    let mut writer = db
        .create_segment(REALM, crate::SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(crate::SegmentPageKind::Data, bytes)
        .await
        .unwrap();
    writer.seal().await.unwrap()
}

/// A reader keeps the source key in this handle's keyring, so the seal succeeds. No
/// later open holds that key, so a row naming it must never land.
#[tokio::test(flavor = "current_thread")]
async fn link_and_replace_refuse_a_segment_sealed_under_an_epoch_the_store_left() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    let current = sealed_page_segment(&db, b"linked-before").await;
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("linked", &current).await.unwrap();
    txn.commit().await.unwrap();
    let mut writer = db
        .create_segment(REALM, crate::SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(crate::SegmentPageKind::Data, b"pinned")
        .await
        .unwrap();
    let reader = db.begin_read().await.unwrap();

    db.rekey_db(KEK0, 1).await.unwrap();
    let stale = writer.seal().await.unwrap();
    assert_eq!(stale.mk_epoch, 0, "the writer keeps the epoch it pinned");

    let mut txn = db.begin_write().await.unwrap();
    let error = txn.link_segment("stale", &stale).await.unwrap_err();
    assert!(
        matches!(
            error,
            PagedbError::SegmentEpochStale {
                segment_epoch: 0,
                store_epoch: 1
            }
        ),
        "got {error:?}"
    );
    let error = txn.replace_segment("linked", &stale).await.unwrap_err();
    assert!(
        matches!(error, PagedbError::SegmentEpochStale { .. }),
        "got {error:?}"
    );
    txn.commit().await.unwrap();
    drop(reader);
    drop(db);

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    assert!(matches!(
        reopened.open_segment(REALM, "stale").await,
        Err(PagedbError::NotFound)
    ));
    let linked = reopened.open_segment(REALM, "linked").await.unwrap();
    assert_eq!(linked.meta().mk_epoch, 1);
    assert_clean_walk(&reopened, "after the refusals").await;
}

/// With no reader, the rekey retires the key the writer pinned. The writer reports
/// that by type and never seals under a key its label does not name.
#[tokio::test(flavor = "current_thread")]
async fn a_writer_whose_pinned_epoch_retired_fails_with_a_typed_error() {
    let db = Db::open_internal(MemVfs::new(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    let mut writer = db
        .create_segment(REALM, crate::SegmentKind::Unspecified)
        .await
        .unwrap();

    db.rekey_db(KEK0, 1).await.unwrap();

    let error = writer
        .append_page(crate::SegmentPageKind::Data, b"late")
        .await
        .unwrap_err();
    assert!(
        matches!(error, PagedbError::MissingPersistedKey { mk_epoch: 0, .. }),
        "got {error:?}"
    );
    assert!(matches!(
        writer.seal().await,
        Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
    ));
}

async fn flip_segment_byte(vfs: &MemVfs, meta: &crate::SegmentMeta, offset: u64) {
    let path = crate::segment::writer::live_path(&meta.segment_id);
    let mut file = vfs.open(&path, OpenMode::ReadWrite).await.unwrap();
    let mut byte = [0u8; 1];
    file.read_at(offset, &mut byte).await.unwrap();
    byte[0] ^= 1;
    file.write_at(offset, &byte).await.unwrap();
    file.sync().await.unwrap();
}

/// The check runs before any write, so the caller can unlink the bad segment and
/// retry with nothing to undo.
#[tokio::test(flavor = "current_thread")]
async fn a_linked_segment_that_cannot_authenticate_refuses_the_rekey_before_any_write() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    let bad = sealed_page_segment(&db, b"bad").await;
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("bad", &bad).await.unwrap();
    txn.commit().await.unwrap();
    flip_segment_byte(&vfs, &bad, PAGE as u64 - 1).await;

    let error = db.rekey_db(KEK0, 1).await.unwrap_err();

    assert!(matches!(error, PagedbError::Corruption(_)), "got {error:?}");
    db.ensure_usable().unwrap();
    {
        let state = db.writer.lock().await;
        assert!(db.load_rekey_intent(&state).await.unwrap().is_none());
    }

    let mut txn = db.begin_write().await.unwrap();
    txn.unlink_segment("bad").await.unwrap();
    txn.commit().await.unwrap();
    db.rekey_db(KEK0, 1).await.unwrap();
    assert_clean_walk(&db, "after the unlink and the retry").await;
}

/// A torn data page passes the check, because only a full read can find it. One such
/// file must not fail every open that resumes the rekey. It keeps its source epoch,
/// so its reads report the missing key until the embedder unlinks it.
#[tokio::test(flavor = "current_thread")]
async fn a_segment_page_the_rekey_cannot_read_stays_behind_and_the_store_opens() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    let bad = sealed_page_segment(&db, b"bad").await;
    let good = sealed_page_segment(&db, b"good").await;
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment("bad", &bad).await.unwrap();
    txn.link_segment("good", &good).await.unwrap();
    txn.commit().await.unwrap();
    write_rows(&db, 1).await;
    flip_segment_byte(&vfs, &bad, PAGE as u64 + 100).await;

    db.rekey_db(KEK0, 1).await.unwrap();
    drop(db);

    let reopened = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    assert_rows_read(&reopened, 1, "beside the bad segment").await;
    assert!(matches!(
        reopened.open_segment(REALM, "bad").await.map(drop),
        Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
    ));
    let segment = reopened.open_segment(REALM, "good").await.unwrap();
    assert_eq!(segment.meta().mk_epoch, 1);
    assert!(segment.read_page(1).await.unwrap().starts_with(b"good"));
    drop(segment);

    let mut txn = reopened.begin_write().await.unwrap();
    txn.unlink_segment("bad").await.unwrap();
    txn.commit().await.unwrap();
    assert_clean_walk(&reopened, "after the unlink").await;
}

/// A cancelled KEK change leaves every page under the source key, so the target key
/// is not needed. The open proves that from the envelopes, then withdraws the intent.
#[tokio::test(flavor = "current_thread")]
async fn an_open_with_the_source_key_alone_withdraws_an_intent_no_page_depends_on() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();
    write_rows(&db, 1).await;
    db.interrupt_rekey_after(RekeyTestFault::MainPagesTargetReadable);
    assert!(db.rekey_db(NEW_KEK, 1).await.is_err());
    write_rows(&db, 2).await;
    drop(db);

    let reopened = Db::open_existing(vfs.clone(), KEK0, PAGE, REALM)
        .await
        .unwrap();

    assert_eq!(reopened.mk_epoch.load(Ordering::SeqCst), 0);
    {
        let state = reopened.writer.lock().await;
        assert!(reopened.load_rekey_intent(&state).await.unwrap().is_none());
    }
    assert!(vfs.open(SCRATCH, OpenMode::Read).await.is_err());
    assert_rows_read(&reopened, 2, "after the withdrawal").await;
    assert_every_page_at_target(&vfs, 0, "after the withdrawal").await;
    assert_clean_walk(&reopened, "after the withdrawal").await;
    drop(reopened);

    let again = Db::open_existing(vfs, KEK0, PAGE, REALM).await.unwrap();
    assert_rows_read(&again, 2, "the next open").await;
}

/// A handle with no recovery authority reads the same store, and writes nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_read_only_open_reads_a_store_whose_pending_rekey_has_no_target_page() {
    for case in KEY_CASES {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), KEK0, PAGE, REALM)
            .await
            .unwrap();
        write_rows(&db, 1).await;
        db.interrupt_rekey_after(RekeyTestFault::MainPagesTargetReadable);
        assert!(db.rekey_db(case.target_kek(), 1).await.is_err(), "{case:?}");
        drop(db);
        vfs.remove(SCRATCH).await.unwrap();
        let header_before = raw_page(&vfs, 0).await.unwrap();

        let reader = Db::open_read_only(vfs.clone(), KEK0, PAGE, REALM, OpenOptions::default())
            .await
            .unwrap_or_else(|error| panic!("{case:?}: the open failed: {error:?}"));

        assert_rows_read(&reader, 1, "read only").await;
        drop(reader);
        assert_eq!(raw_page(&vfs, 0).await.unwrap(), header_before, "{case:?}");
    }
}
