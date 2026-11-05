//! A stale commit-history row must not stop a rekey or the open that resumes it.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use crate::btree::BTree;
use crate::catalog::codec::{RekeyIntent, RekeyStage};
use crate::errors::CorruptionDetail;
use crate::txn::db::catalog::history_policy::proves_unreadable_pages;
use crate::txn::db::core::{RekeyTestFault, decode_commit_meta, encode_commit_meta};
use crate::txn::db::rekey::main::RekeyCatalogCommit;
use crate::vfs::gated::GatedVfs;
use crate::vfs::memory::MemVfs;
use crate::vfs::{OpenMode, Vfs, VfsFile};
use crate::{CommitId, Db, OpenOptions, PagedbError, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0xB4; 32];
const REALM: RealmId = RealmId::new([0xB5; 16]);
const COMMITS: u8 = 4;
/// Enough rows that the history index spans more than one page.
const INDEX_SPANNING_COMMITS: u8 = 200;
/// Clear of every page a rekey allocates, so a cut there removes none of them.
const PAST_CURSOR_GAP: u64 = 64;

async fn commit_versions<V: Vfs + Clone>(db: &Db<V>, count: u8) -> Vec<CommitId> {
    let mut commits = Vec::new();
    for version in 0..count {
        let mut txn = db.begin_write().await.unwrap();
        txn.put(b"versioned", &[version]).await.unwrap();
        commits.push(txn.commit().await.unwrap());
    }
    commits
}

async fn root_of<V: Vfs + Clone>(db: &Db<V>, commit: CommitId) -> u64 {
    db.begin_read_at(commit).await.unwrap().root_page_id()
}

/// Keep a page's leading bytes and replace the rest, so its tag fails.
async fn tear_page<V: Vfs + Clone>(vfs: &V, page_id: u64) {
    let offset = page_id * PAGE as u64 + (PAGE / 2) as u64;
    let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    file.write_at(offset, &[0xEE; PAGE / 2]).await.unwrap();
    file.sync().await.unwrap();
}

async fn assert_gone<V: Vfs + Clone>(db: &Db<V>, commit: CommitId, oldest: CommitId) {
    match db.begin_read_at(commit).await {
        Err(PagedbError::CommitGone {
            commit: gone,
            oldest_available,
        }) => {
            assert_eq!(gone, commit);
            assert_eq!(oldest_available, oldest);
        }
        Err(error) => panic!("{commit:?} reported {error:?}, not CommitGone"),
        Ok(_) => panic!("{commit:?} still admits a reader"),
    }
}

async fn assert_reads_version<V: Vfs + Clone>(db: &Db<V>, commit: CommitId, version: u8) {
    let reader = db
        .begin_read_at(commit)
        .await
        .unwrap_or_else(|error| panic!("{commit:?} refused a reader: {error:?}"));
    assert_eq!(
        reader.get(b"versioned").await.unwrap().as_deref(),
        Some([version].as_slice()),
        "{commit:?} holds another version"
    );
}

/// Rows at `commits[..2]` are gone, and the rest read their own values.
async fn assert_pruned_through_second(db: &Db<MemVfs>, commits: &[CommitId]) {
    assert_gone(db, commits[0], commits[2]).await;
    assert_gone(db, commits[1], commits[2]).await;
    assert_reads_version(db, commits[2], 2).await;
    assert_reads_version(db, commits[3], 3).await;
    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"versioned").await.unwrap().as_deref(),
        Some([3].as_slice())
    );
    drop(reader);
    let report = crate::recovery::deep_walk::run_deep_walk(db).await.unwrap();
    assert!(report.is_clean(), "deep walk report: {report:?}");
}

/// The tear reaches the second row. That row and the older one leave durably.
#[tokio::test(flavor = "current_thread")]
async fn rekey_prunes_a_stale_row_and_every_older_row_and_the_store_reopens() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let commits = commit_versions(&db, COMMITS).await;
    tear_page(&vfs, root_of(&db, commits[1]).await).await;
    db.evict_main_pages().unwrap();

    db.rekey_db(KEK, 1).await.unwrap();
    assert_gone(&db, commits[1], commits[2]).await;
    drop(db);

    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    assert_pruned_through_second(&reopened, &commits).await;
}

/// At an epoch above zero a row's bound is `oldest`, so the torn page's tag sits
/// at the bound. No surviving row reaches that page, so it must not stop the pass.
#[tokio::test(flavor = "current_thread")]
async fn rekey_above_epoch_zero_prunes_a_stale_row_whose_page_sits_at_the_bound() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    db.rekey_db(KEK, 1).await.unwrap();
    let commits = commit_versions(&db, COMMITS).await;
    tear_page(&vfs, root_of(&db, commits[1]).await).await;
    db.evict_main_pages().unwrap();

    db.rekey_db(KEK, 2).await.unwrap();
    drop(db);

    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    assert_pruned_through_second(&reopened, &commits).await;
}

/// The intent is already durable when the row goes stale. An intent from an
/// earlier release reaches the same state. The resume reads a mix of epochs.
#[tokio::test(flavor = "current_thread")]
async fn a_resume_prunes_a_stale_row_at_every_stage_with_a_pass_left() {
    let boundaries = [
        RekeyTestFault::Intent,
        RekeyTestFault::MainPagesTargetReadable,
        RekeyTestFault::HeaderTargetPublished,
    ];
    for point in boundaries {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
            .await
            .unwrap();
        let commits = commit_versions(&db, COMMITS).await;
        let stale_root = root_of(&db, commits[1]).await;
        db.interrupt_rekey_after(point);
        assert!(db.rekey_db(KEK, 1).await.is_err(), "{point:?}");
        drop(db);
        tear_page(&vfs, stale_root).await;

        let reopened = Db::open_existing(vfs, KEK, PAGE, REALM)
            .await
            .unwrap_or_else(|error| panic!("{point:?}: the resume failed: {error:?}"));
        {
            let state = reopened.writer.lock().await;
            assert!(
                reopened.load_rekey_intent(&state).await.unwrap().is_none(),
                "{point:?}: the resume clears its intent"
            );
        }
        assert!(
            matches!(
                reopened.pager.mk_for(0, reopened.cipher_id),
                Err(PagedbError::MissingPersistedKey { mk_epoch: 0, .. })
            ),
            "{point:?}: a completed rekey retires the source epoch"
        );
        assert_pruned_through_second(&reopened, &commits).await;
    }
}

/// An I/O error says nothing about the page bytes. The rekey fails before any
/// write, every row stays, and a retry succeeds.
#[tokio::test(flavor = "current_thread")]
async fn a_transient_read_error_fails_the_rekey_and_prunes_nothing() {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let commits = commit_versions(&db, COMMITS).await;
    let stale_root = root_of(&db, commits[1]).await;
    let history_root = db.writer.lock().await.commit_history_root_page_id;
    db.evict_main_pages().unwrap();
    vfs.fail_next_read_at("/main.db", stale_root * PAGE as u64);

    let error = db.rekey_db(KEK, 1).await.unwrap_err();

    assert!(matches!(error, PagedbError::Io(_)), "got {error:?}");
    db.ensure_usable().unwrap();
    assert_eq!(db.mk_epoch.load(Ordering::SeqCst), 0);
    {
        let state = db.writer.lock().await;
        assert_eq!(state.commit_history_root_page_id, history_root);
        assert!(db.load_rekey_intent(&state).await.unwrap().is_none());
    }
    for (version, &commit) in (0u8..).zip(&commits) {
        assert_reads_version(&db, commit, version).await;
    }

    db.rekey_db(KEK, 1).await.unwrap();
    for (version, &commit) in (0u8..).zip(&commits) {
        assert_reads_version(&db, commit, version).await;
    }
}

/// No prune repairs a live page. The rekey refuses with no intent on disk, so
/// the store still opens, and the rows stay.
#[tokio::test(flavor = "current_thread")]
async fn a_torn_live_page_refuses_the_rekey_and_writes_no_intent() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let commits = commit_versions(&db, COMMITS).await;
    let (live_root, history_root) = {
        let state = db.writer.lock().await;
        (state.root_page_id, state.commit_history_root_page_id)
    };
    tear_page(&vfs, live_root).await;
    db.evict_main_pages().unwrap();

    let error = db.rekey_db(KEK, 1).await.unwrap_err();

    assert!(matches!(error, PagedbError::Corruption(_)), "got {error:?}");
    db.ensure_usable().unwrap();
    {
        let state = db.writer.lock().await;
        assert_eq!(state.commit_history_root_page_id, history_root);
        assert!(db.load_rekey_intent(&state).await.unwrap().is_none());
    }
    assert_reads_version(&db, commits[0], 0).await;
    drop(db);

    assert!(Db::open_existing(vfs, KEK, PAGE, REALM).await.is_ok());
}

/// An index that cannot authenticate names no row a reader can trust. Every row
/// leaves, and its pages stay on disk because a partial walk cannot free them.
///
/// The deep walk reports each one, because none authenticates. The torn page has
/// no valid tag, and the source epoch sealing the others is retired. None counts
/// as an orphan. A compaction rebuilds the file and clears them.
#[tokio::test(flavor = "current_thread")]
async fn a_torn_history_index_removes_every_row_and_stays_reported_until_a_compaction() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let commits = commit_versions(&db, INDEX_SPANNING_COMMITS).await;
    let (history_root, next_page_id) = {
        let state = db.writer.lock().await;
        (state.commit_history_root_page_id, state.next_page_id)
    };
    let mut index_pages = BTreeSet::new();
    BTree::open(db.pager.clone(), REALM, history_root, next_page_id, PAGE)
        .collect_all_page_ids(&mut index_pages)
        .await
        .unwrap();
    assert!(
        index_pages.len() > 1,
        "setup error: the index fits one page, {index_pages:?}"
    );
    tear_page(&vfs, history_root).await;
    db.evict_main_pages().unwrap();

    db.rekey_db(KEK, 1).await.unwrap();
    drop(db);

    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    assert_eq!(reopened.writer.lock().await.commit_history_root_page_id, 0);
    let (&latest, older) = commits.split_last().unwrap();
    for &commit in older {
        assert_gone(&reopened, commit, latest).await;
    }
    assert_reads_version(&reopened, latest, INDEX_SPANNING_COMMITS - 1).await;

    let report = crate::recovery::deep_walk::run_deep_walk(&reopened)
        .await
        .unwrap();
    let reported: Vec<(u64, &str)> = report
        .page_issues
        .iter()
        .map(|issue| (issue.page_id, issue.description.as_str()))
        .collect();
    let expected: Vec<(u64, &str)> = index_pages
        .iter()
        .map(|&page_id| (page_id, "AEAD verification failed"))
        .collect();
    assert_eq!(reported, expected);
    assert!(report.orphan_page_ids.is_empty(), "{report:?}");
    assert!(!report.is_clean());

    reopened.compact_now().await.unwrap();
    let report = crate::recovery::deep_walk::run_deep_walk(&reopened)
        .await
        .unwrap();
    assert!(report.is_clean(), "deep walk report: {report:?}");
}

/// Each way a row's page goes bad without a failed tag.
#[derive(Clone, Copy, Debug)]
enum RowPageDamage {
    /// A value `CipherId::from_byte` refuses.
    GarbledCipherByte,
    /// An epoch no key serves.
    GarbledEpoch,
    /// The file ends before the page starts.
    FileEndsBeforePage,
}

const ROW_PAGE_DAMAGE: [RowPageDamage; 3] = [
    RowPageDamage::GarbledCipherByte,
    RowPageDamage::GarbledEpoch,
    RowPageDamage::FileEndsBeforePage,
];

/// Point the row at `commit` at a copy of its root page, past every page the
/// store names. Cutting the file there then removes that page and nothing live.
async fn move_row_root_past_the_cursor(db: &Db<MemVfs>, commit: CommitId) -> u64 {
    let mut state = db.writer.lock().await;
    let key = commit.0.to_be_bytes();
    let mut history = BTree::open(
        db.pager.clone(),
        REALM,
        state.commit_history_root_page_id,
        state.next_page_id,
        PAGE,
    );
    let row = history.get(&key).await.unwrap().unwrap();
    let mut meta = decode_commit_meta(&row).unwrap();
    let (guard, kind) = db
        .pager
        .read_main_node(meta.active_root_page_id, REALM)
        .await
        .unwrap();
    let body = guard.body_ref().to_vec();
    drop(guard);

    let moved = state.next_page_id + PAST_CURSOR_GAP;
    db.pager
        .write_main_page(moved, REALM, kind, &body)
        .await
        .unwrap();
    meta.active_root_page_id = moved;
    meta.next_page_id = moved + 1;
    history.put(&key, &encode_commit_meta(&meta)).await.unwrap();
    history.flush().await.unwrap();
    db.pager.flush_main(REALM).await.unwrap();

    state.commit_history_root_page_id = history.root_page_id();
    let freed_pages = history.drain_freed();
    let catalog_root_page_id = state.catalog_root_page_id;
    let header_epoch = db.mk_epoch.load(Ordering::SeqCst);
    let header_hk = db.hk.read().clone();
    db.commit_rekey_catalog_root(
        &mut state,
        RekeyCatalogCommit {
            catalog_root_page_id,
            next_page_id: history.next_page_id(),
            freed_pages: &freed_pages,
            effects: &[],
        },
        header_epoch,
        &header_hk,
    )
    .await
    .unwrap();
    moved
}

async fn page_to_damage(db: &Db<MemVfs>, commit: CommitId, damage: RowPageDamage) -> u64 {
    match damage {
        RowPageDamage::GarbledCipherByte | RowPageDamage::GarbledEpoch => root_of(db, commit).await,
        RowPageDamage::FileEndsBeforePage => move_row_root_past_the_cursor(db, commit).await,
    }
}

async fn damage_page(vfs: &MemVfs, page_id: u64, damage: RowPageDamage) {
    let offset = page_id * PAGE as u64;
    let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    match damage {
        RowPageDamage::GarbledCipherByte => {
            file.write_at(offset, &[0xFE]).await.unwrap();
        }
        RowPageDamage::GarbledEpoch => {
            file.write_at(offset + 4, &[0xFE; 8]).await.unwrap();
        }
        RowPageDamage::FileEndsBeforePage => file.truncate(offset).await.unwrap(),
    }
    file.sync().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn rekey_prunes_a_row_whose_page_lost_its_envelope_or_lies_past_the_file() {
    for damage in ROW_PAGE_DAMAGE {
        let vfs = MemVfs::new();
        let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
            .await
            .unwrap();
        let commits = commit_versions(&db, COMMITS).await;
        let page_id = page_to_damage(&db, commits[1], damage).await;
        assert_reads_version(&db, commits[1], 1).await;
        damage_page(&vfs, page_id, damage).await;
        db.evict_main_pages().unwrap();

        db.rekey_db(KEK, 1)
            .await
            .unwrap_or_else(|error| panic!("{damage:?}: the rekey failed: {error:?}"));
        drop(db);

        let reopened = Db::open_existing(vfs, KEK, PAGE, REALM)
            .await
            .unwrap_or_else(|error| panic!("{damage:?}: the open failed: {error:?}"));
        assert_pruned_through_second(&reopened, &commits).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_resume_prunes_a_row_whose_page_lost_its_envelope_or_lies_past_the_file() {
    let boundaries = [
        RekeyTestFault::Intent,
        RekeyTestFault::MainPagesTargetReadable,
        RekeyTestFault::HeaderTargetPublished,
    ];
    for damage in ROW_PAGE_DAMAGE {
        for point in boundaries {
            let vfs = MemVfs::new();
            let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
                .await
                .unwrap();
            let commits = commit_versions(&db, COMMITS).await;
            let page_id = page_to_damage(&db, commits[1], damage).await;
            db.interrupt_rekey_after(point);
            assert!(db.rekey_db(KEK, 1).await.is_err(), "{damage:?} {point:?}");
            drop(db);
            damage_page(&vfs, page_id, damage).await;

            let reopened = Db::open_existing(vfs, KEK, PAGE, REALM)
                .await
                .unwrap_or_else(|error| {
                    panic!("{damage:?} {point:?}: the resume failed: {error:?}")
                });
            assert_pruned_through_second(&reopened, &commits).await;
        }
    }
}

/// `MissingPersistedKey` proves nothing about a page while an intent key is
/// absent. The gate fails first, before any walk can prune.
#[tokio::test(flavor = "current_thread")]
async fn a_resume_missing_an_intent_key_fails_and_prunes_nothing() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let commits = commit_versions(&db, COMMITS).await;
    tear_page(&vfs, root_of(&db, commits[1]).await).await;
    db.evict_main_pages().unwrap();
    let cipher_id = db.cipher_id.as_byte();
    let intent = RekeyIntent {
        source_mk_epoch: 0,
        target_mk_epoch: 9,
        source_cipher_id: cipher_id,
        target_cipher_id: cipher_id,
        same_kek: true,
        stage: RekeyStage::Intent,
        source_hk_proof: [0; 16],
        target_hk_proof: [0; 16],
    };
    let mut state = db.writer.lock().await;
    let history_root = state.commit_history_root_page_id;

    let error = db
        .settle_history_for_resume(&mut state, &intent)
        .await
        .unwrap_err();

    assert!(
        matches!(error, PagedbError::MissingPersistedKey { mk_epoch: 9, .. }),
        "got {error:?}"
    );
    assert_eq!(state.commit_history_root_page_id, history_root);
}

/// The single classifier every durable decision uses. A variant a backend or a
/// caller can raise stays out, even when a torn page once raised it too.
#[test]
fn the_classifier_accepts_only_errors_a_page_read_can_blame_on_the_page() {
    let eof = std::io::ErrorKind::UnexpectedEof;
    let table: [(&str, PagedbError, bool); 11] = [
        ("tag failure", PagedbError::ChecksumFailure, true),
        ("kind byte", PagedbError::IllegalPageKind, true),
        (
            "corruption",
            PagedbError::corruption(CorruptionDetail::CatalogRowInvalid { field: "probe" }),
            true,
        ),
        (
            "epoch in the envelope",
            PagedbError::MissingPersistedKey {
                mk_epoch: 7,
                cipher_id: 1,
            },
            true,
        ),
        (
            "file ends before the page",
            PagedbError::Io(std::io::Error::from(eof)),
            true,
        ),
        ("backend reply", PagedbError::Unsupported, false),
        (
            "transient I/O",
            PagedbError::Io(std::io::Error::other("probe")),
            false,
        ),
        (
            "interrupted read",
            PagedbError::Io(std::io::Error::from(std::io::ErrorKind::Interrupted)),
            false,
        ),
        ("read-only handle", PagedbError::ReadOnly, false),
        (
            "missing counterpart key",
            PagedbError::rekey_resume_key_required(0, 1),
            false,
        ),
        (
            "wrong counterpart key",
            PagedbError::rekey_counterpart_key_invalid(0, 1),
            false,
        ),
    ];
    for (name, error, proof) in &table {
        assert_eq!(proves_unreadable_pages(error), *proof, "{name}: {error:?}");
    }
}

/// A garbled cipher byte reaches the caller as damage to that page, so the
/// classifier need not trust `Unsupported`, which a VFS raises too.
#[tokio::test(flavor = "current_thread")]
async fn a_garbled_cipher_byte_reads_as_an_unverifiable_page() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let commits = commit_versions(&db, COMMITS).await;
    let page_id = root_of(&db, commits[1]).await;
    damage_page(&vfs, page_id, RowPageDamage::GarbledCipherByte).await;
    db.evict_main_pages().unwrap();

    let outcome = db.pager.read_main_node(page_id, REALM).await.map(drop);

    assert!(
        matches!(
            outcome,
            Err(PagedbError::Corruption(CorruptionDetail::PageUnverifiable {
                page_id: reported,
                ..
            })) if reported == page_id
        ),
        "got {outcome:?}"
    );
}
