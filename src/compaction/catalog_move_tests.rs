//! A follower can sit on either side of a catalog root that moved without a
//! commit row: a rekey, `set_realm_quotas`, or a segment repack.
//!
//! These live beside `replace_segment_compact`, because a full `compact_now` runs
//! a main repack first, and that empties the rows this path has to keep.

use tempfile::TempDir;

use crate::catalog::codec::{SegmentKind, SegmentMeta};
use crate::options::RetainPolicy;
use crate::pager::PageKind;
use crate::pager::format::data_page::body_capacity;
use crate::recovery::deep_walk::run_deep_walk;
use crate::segment::types::SegmentPageKind;
use crate::vfs::tokio_backend::TokioVfs;
use crate::{CommitId, Db, OpenOptions, PagedbError, RealmId, RealmQuotas};

use super::helpers::replace_segment_compact;

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x6C; 32];
const REALM: RealmId = RealmId::new([0x6D; 16]);
const SEGMENT: &str = "engine.idx";
const VERSIONS: u8 = 3;
const TARGET_VERSION: u8 = 9;
/// Commits and rows per commit a store gets to draw a free page.
const DRAW_ROUNDS: u32 = 32;
const DRAW_ROWS: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CatalogMove {
    Rekey,
    /// A rekey over a store with a page no root and no free list names.
    RekeyOverOrphan,
    Quotas,
    SegmentRepack,
}

/// A snapshot taken before the move, or after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Restored {
    BeforeMove,
    AfterMove,
}

/// Fields drop in order, so the handles close before the directories leave.
struct Fixture {
    source: Db<TokioVfs>,
    follower: Db<TokioVfs>,
    rows: Vec<CommitId>,
    delta_dir: TempDir,
    /// The page a `RekeyOverOrphan` sealed, which a later commit drew.
    orphan: Option<u64>,
    _dirs: [TempDir; 3],
}

async fn sealed_segment(db: &Db<TokioVfs>, bytes: &[u8]) -> SegmentMeta {
    let mut writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(SegmentPageKind::Data, bytes)
        .await
        .unwrap();
    writer.seal().await.unwrap()
}

async fn repack_segment(db: &Db<TokioVfs>, old: &SegmentMeta, new: &SegmentMeta) {
    let mut state = db.writer.lock().await;
    let visibility = db.visibility_gate.write().await;
    replace_segment_compact(db, &mut state, &visibility, SEGMENT, &old.segment_id, new)
        .await
        .unwrap();
}

async fn commit_version(db: &Db<TokioVfs>, version: u8) -> CommitId {
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"versioned", &[version]).await.unwrap();
    txn.commit().await.unwrap()
}

async fn restore_follower(source: &Db<TokioVfs>, snap: &TempDir, dst: &TempDir) -> Db<TokioVfs> {
    source.snapshot_to(snap.path()).await.unwrap();
    Db::<TokioVfs>::restore_from(snap.path(), dst.path(), OpenOptions::default(), KEK)
        .await
        .unwrap()
        .promote_to_follower()
        .await
        .unwrap()
}

/// Commit overflow values until the data tree reaches `page_id`. The allocator draws
/// from the free list, so this is what proves the commit drew that page. A chain
/// host does not count, because no delta ships one. Reports whether that happened.
async fn commit_until_drawn(db: &Db<TokioVfs>, page_id: u64) -> bool {
    for round in 0..DRAW_ROUNDS {
        let mut txn = db.begin_write().await.unwrap();
        for row in 0..DRAW_ROWS {
            txn.put(format!("draw-{round}-{row}").as_bytes(), &[0xDD; 3000])
                .await
                .unwrap();
        }
        txn.commit().await.unwrap();
        let (root, next) = {
            let state = db.writer.lock().await;
            (state.root_page_id, state.next_page_id)
        };
        let mut reachable = std::collections::BTreeSet::new();
        crate::btree::BTree::open(db.pager.clone(), REALM, root, next, PAGE)
            .collect_all_page_ids(&mut reachable)
            .await
            .unwrap();
        if reachable.contains(&page_id) {
            return true;
        }
    }
    false
}

/// Seal a page no root and no free list names, under the store's current key.
async fn seal_orphan_below_the_cursor(db: &Db<TokioVfs>) -> u64 {
    let page_id = {
        let mut state = db.writer.lock().await;
        let page_id = state.next_page_id;
        state.next_page_id = page_id + 1;
        page_id
    };
    db.pager
        .write_main_page(
            page_id,
            REALM,
            PageKind::BTreeLeaf,
            &vec![0x5A; body_capacity(PAGE)],
        )
        .await
        .unwrap();
    db.pager.flush_main(REALM).await.unwrap();
    page_id
}

/// Rows, a catalog move, a follower restored on the chosen side, then one more
/// producer commit exported from the follower's commit.
async fn fixture(catalog_move: CatalogMove, restored: Restored) -> Fixture {
    let (src, snap, dst) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let delta_dir = tempfile::tempdir().unwrap();
    let source = Db::open(
        TokioVfs::new(src.path()),
        KEK,
        PAGE,
        REALM,
        OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded),
    )
    .await
    .unwrap();

    let segments = if catalog_move == CatalogMove::SegmentRepack {
        let old = sealed_segment(&source, b"old-bytes").await;
        let mut txn = source.begin_write().await.unwrap();
        txn.link_segment(SEGMENT, &old).await.unwrap();
        txn.commit().await.unwrap();
        Some((old, sealed_segment(&source, b"new-bytes").await))
    } else {
        None
    };
    let mut rows = Vec::new();
    for version in 0..VERSIONS {
        rows.push(commit_version(&source, version).await);
    }

    let mut follower = None;
    if restored == Restored::BeforeMove {
        follower = Some(restore_follower(&source, &snap, &dst).await);
    }
    let mut orphan = None;
    match catalog_move {
        CatalogMove::Rekey => source.rekey_db(KEK, 1).await.unwrap(),
        CatalogMove::RekeyOverOrphan => {
            orphan = Some(seal_orphan_below_the_cursor(&source).await);
            source.rekey_db(KEK, 1).await.unwrap();
        }
        CatalogMove::Quotas => source
            .set_realm_quotas(REALM, RealmQuotas::default().with_max_pages(1 << 20))
            .await
            .unwrap(),
        CatalogMove::SegmentRepack => {
            let (old, new) = segments.as_ref().unwrap();
            repack_segment(&source, old, new).await;
        }
    }
    let follower = match follower {
        Some(follower) => follower,
        None => restore_follower(&source, &snap, &dst).await,
    };

    let base = follower.latest_commit();
    if let Some(page_id) = orphan {
        assert!(
            commit_until_drawn(&source, page_id).await,
            "setup error: {DRAW_ROUNDS} commits never drew page {page_id}"
        );
    }
    commit_version(&source, TARGET_VERSION).await;
    source
        .snapshot_incremental_to(base, delta_dir.path())
        .await
        .unwrap();
    Fixture {
        source,
        follower,
        rows,
        delta_dir,
        orphan,
        _dirs: [src, snap, dst],
    }
}

async fn assert_latest_and_every_row_read_their_values(fixture: &Fixture) {
    let follower = &fixture.follower;
    let reader = follower.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"versioned").await.unwrap().as_deref(),
        Some([TARGET_VERSION].as_slice())
    );
    drop(reader);
    for (version, commit) in fixture.rows.iter().enumerate() {
        let reader = follower.begin_read_at(*commit).await.unwrap();
        assert_eq!(
            reader.get(b"versioned").await.unwrap().as_deref(),
            Some([u8::try_from(version).unwrap()].as_slice()),
            "{commit:?} left the retained commit"
        );
    }
    let report = run_deep_walk(follower).await.unwrap();
    assert!(report.is_clean(), "{report:?}");
}

async fn assert_apply_reads_correctly(catalog_move: CatalogMove, restored: Restored) {
    let fixture = fixture(catalog_move, restored).await;
    fixture
        .follower
        .apply_incremental(fixture.delta_dir.path())
        .await
        .unwrap_or_else(|error| panic!("{catalog_move:?} {restored:?}: {error:?}"));
    assert_eq!(
        fixture.follower.latest_commit(),
        fixture.source.latest_commit()
    );
    assert_latest_and_every_row_read_their_values(&fixture).await;
    if catalog_move == CatalogMove::SegmentRepack {
        let segment = fixture.follower.open_segment(REALM, SEGMENT).await.unwrap();
        assert!(
            segment
                .read_page(1)
                .await
                .unwrap()
                .starts_with(b"new-bytes")
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_follower_restored_after_a_rekey_applies_its_first_delta() {
    assert_apply_reads_correctly(CatalogMove::Rekey, Restored::AfterMove).await;
}

/// The producer's rebuild turned the orphan into a free zero hole. The next commits
/// draw it, so the delta ships that page as a new one over the follower's hole.
#[tokio::test(flavor = "current_thread")]
async fn a_follower_restored_after_a_rekey_over_an_orphan_applies_a_delta_that_drew_the_hole() {
    let fixture = fixture(CatalogMove::RekeyOverOrphan, Restored::AfterMove).await;
    let orphan = fixture
        .orphan
        .expect("setup error: the fixture sealed no orphan");
    let head = fixture.source.writer.lock().await.free_list_root_page_id;
    let (free_entries, _) = crate::pager::freelist::read_chain(&fixture.source.pager, REALM, head)
        .await
        .unwrap();
    assert!(
        free_entries.iter().all(|&(_, page_id)| page_id != orphan),
        "setup error: no commit drew page {orphan}"
    );
    let report = run_deep_walk(&fixture.source).await.unwrap();
    assert!(report.is_clean(), "{report:?}");

    fixture
        .follower
        .apply_incremental(fixture.delta_dir.path())
        .await
        .unwrap();
    assert_eq!(
        fixture.follower.latest_commit(),
        fixture.source.latest_commit()
    );
    assert_latest_and_every_row_read_their_values(&fixture).await;
    let drawn = fixture
        .follower
        .pager
        .read_main_node(orphan, REALM)
        .await
        .map(drop);
    let overflow = fixture
        .follower
        .pager
        .read_main_page(orphan, REALM, PageKind::OverflowRoot)
        .await
        .map(drop);
    assert!(
        drawn.is_ok() || overflow.is_ok(),
        "page {orphan} is not on the follower: {drawn:?} {overflow:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_follower_restored_after_a_quota_write_applies_its_first_delta() {
    assert_apply_reads_correctly(CatalogMove::Quotas, Restored::AfterMove).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_follower_restored_before_a_quota_write_applies_across_it() {
    assert_apply_reads_correctly(CatalogMove::Quotas, Restored::BeforeMove).await;
}

/// The repack bumped the commit id and wrote no row, so the export needs the row
/// the next commit backfills.
#[tokio::test(flavor = "current_thread")]
async fn a_follower_restored_after_a_segment_repack_applies_its_first_delta() {
    assert_apply_reads_correctly(CatalogMove::SegmentRepack, Restored::AfterMove).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_follower_restored_before_a_segment_repack_applies_across_it() {
    assert_apply_reads_correctly(CatalogMove::SegmentRepack, Restored::BeforeMove).await;
}

/// A record the base already holds byte for byte writes nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_record_matching_the_base_page_is_not_counted_as_applied() {
    let fixture = fixture(CatalogMove::Quotas, Restored::AfterMove).await;
    let delta = std::fs::read(fixture.delta_dir.path().join("pages.delta")).unwrap();
    let records = u64::try_from(delta.len() / (8 + PAGE)).unwrap();

    let stats = fixture
        .follower
        .apply_incremental(fixture.delta_dir.path())
        .await
        .unwrap();

    assert!(
        stats.pages_applied < records,
        "{} of {records} records wrote a page",
        stats.pages_applied
    );
}

/// Flip one byte of the record naming the follower's live catalog root.
fn corrupt_catalog_root_record(delta_dir: &TempDir, catalog_root: u64) {
    let path = delta_dir.path().join("pages.delta");
    let mut delta = std::fs::read(&path).unwrap();
    let record = delta
        .as_chunks_mut::<{ 8 + PAGE }>()
        .0
        .iter_mut()
        .find(|record| record[..8] == catalog_root.to_be_bytes())
        .expect("setup error: the delta does not name the live catalog root");
    record[8 + PAGE - 1] ^= 1;
    std::fs::write(&path, delta).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_base_live_record_with_different_bytes_is_still_refused() {
    let fixture = fixture(CatalogMove::Quotas, Restored::AfterMove).await;
    let base = fixture.follower.latest_commit();
    let catalog_root = fixture.follower.writer.lock().await.catalog_root_page_id;
    corrupt_catalog_root_record(&fixture.delta_dir, catalog_root);

    let error = fixture
        .follower
        .apply_incremental(fixture.delta_dir.path())
        .await
        .expect_err("different bytes over a live page must be refused");

    assert!(
        matches!(error, PagedbError::SnapshotBasePageReused { page_id } if page_id == catalog_root),
        "{error:?}"
    );
    assert_eq!(fixture.follower.latest_commit(), base);
}

/// The producer's header key moved with its epoch, so the manifest MAC cannot
/// verify here. The follower names the epoch and stays intact, and a full snapshot
/// is the way forward.
#[tokio::test(flavor = "current_thread")]
async fn a_follower_from_before_a_rekey_refuses_a_later_delta_as_incompatible() {
    let fixture = fixture(CatalogMove::Rekey, Restored::BeforeMove).await;
    let base = fixture.follower.latest_commit();

    let error = fixture
        .follower
        .apply_incremental(fixture.delta_dir.path())
        .await
        .expect_err("a delta from a later epoch cannot apply");

    assert!(
        matches!(
            error,
            PagedbError::SnapshotIncompatible { field: "mk_epoch" }
        ),
        "{error:?}"
    );
    assert_eq!(fixture.follower.latest_commit(), base);
    let reader = fixture.follower.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"versioned").await.unwrap().as_deref(),
        Some([VERSIONS - 1].as_slice())
    );
}

/// A main repack resets the rows on purpose, so the commit it publishes has no row
/// and the next commit backfills none. The export refuses by type.
#[tokio::test(flavor = "current_thread")]
async fn an_export_from_the_commit_of_a_main_repack_reports_commit_gone() {
    let src = tempfile::tempdir().unwrap();
    let delta_dir = tempfile::tempdir().unwrap();
    let source = Db::open(
        TokioVfs::new(src.path()),
        KEK,
        PAGE,
        REALM,
        OpenOptions::default().with_commit_history_retain(RetainPolicy::Count(1)),
    )
    .await
    .unwrap();
    for version in 0..8 {
        commit_version(&source, version).await;
    }
    source.compact_now().await.unwrap();
    assert_eq!(
        source.writer.lock().await.commit_history_root_page_id,
        0,
        "setup error: the main repack did not run"
    );
    let base = source.latest_commit();
    commit_version(&source, TARGET_VERSION).await;

    let result = source.snapshot_incremental_to(base, delta_dir.path()).await;

    assert!(matches!(result, Err(PagedbError::CommitGone { .. })));
}

/// The row the next commit writes names the repacked commit's own roots.
#[tokio::test(flavor = "current_thread")]
async fn a_backfilled_row_reads_the_repacked_commits_data() {
    let fixture = fixture(CatalogMove::SegmentRepack, Restored::AfterMove).await;
    let base = fixture.follower.latest_commit();

    let reader = fixture.source.begin_read_at(base).await.unwrap();
    assert_eq!(
        reader.get(b"versioned").await.unwrap().as_deref(),
        Some([VERSIONS - 1].as_slice()),
        "the backfilled row must name the repacked commit's data"
    );
}
