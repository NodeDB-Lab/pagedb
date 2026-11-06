//! Retained rows an earlier apply overwrote: seal order must find them, and must
//! never condemn an intact row.

use std::collections::BTreeMap;

use crate::options::RetainPolicy;
use crate::pager::PageKind;
use crate::vfs::tokio_backend::TokioVfs;
use crate::{
    CipherId, CommitId, Db, DbMode, HistorySealVerdict, OpenOptions, PagedbError, RealmId,
    SealOrderVoid, StaleRowEvidence, run_deep_walk,
};

pub(super) const PAGE: usize = 4096;
pub(super) const KEK: [u8; 32] = [7u8; 32];
pub(super) const REALM: RealmId = RealmId::new([1u8; 16]);
const KEYS: u32 = 200;
pub(super) const VALUE_LEN: usize = 128;
const OVERWRITTEN: [u8; VALUE_LEN] = [0xEE; VALUE_LEN];

/// Directories that leave with the test, passed or failed.
pub(super) struct Scratch {
    root: tempfile::TempDir,
    next: std::cell::Cell<u32>,
}

impl Scratch {
    pub(super) fn new() -> Self {
        Self {
            root: tempfile::Builder::new()
                .prefix("pagedb-stale-")
                .tempdir()
                .unwrap(),
            next: std::cell::Cell::new(0),
        }
    }

    pub(super) fn dir(&self) -> std::path::PathBuf {
        let index = self.next.get();
        self.next.set(index + 1);
        let path = self.root.path().join(index.to_string());
        std::fs::create_dir_all(&path).unwrap();
        path
    }
}

pub(super) fn key(index: u32) -> Vec<u8> {
    format!("stale-{index:05}").into_bytes()
}

pub(super) fn unbounded() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Unbounded)
}

pub(super) async fn open_source(root: &std::path::Path, options: OpenOptions) -> Db<TokioVfs> {
    Db::open(TokioVfs::new(root), KEK, PAGE, REALM, options)
        .await
        .unwrap()
}

/// Rewrites every key, so each row reaches leaves no other row reaches.
pub(super) async fn commit_all(db: &Db<TokioVfs>, value: u8) -> CommitId {
    let mut write = db.begin_write().await.unwrap();
    for index in 0..KEYS {
        write.put(&key(index), &[value; VALUE_LEN]).await.unwrap();
    }
    write.commit().await.unwrap()
}

/// `values[i]` is the value of `commits[i]`.
///
/// Fields drop in order, so both handles close before the directories leave.
struct Fixture {
    source: Db<TokioVfs>,
    follower: Db<TokioVfs>,
    commits: Vec<CommitId>,
    values: Vec<u8>,
    next_value: u8,
    scratch: Scratch,
}

async fn follower_with_rows(rows: u8) -> Fixture {
    let scratch = Scratch::new();
    let source = open_source(&scratch.dir(), unbounded()).await;
    let mut commits = Vec::new();
    let mut values = Vec::new();
    for value in 1..=rows {
        commits.push(commit_all(&source, value).await);
        values.push(value);
    }
    let snap_dir = scratch.dir();
    source.snapshot_to(&snap_dir).await.unwrap();
    let restored =
        Db::<TokioVfs>::restore_from(&snap_dir, &scratch.dir(), OpenOptions::default(), KEK)
            .await
            .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    Fixture {
        source,
        follower,
        commits,
        values,
        next_value: rows + 1,
        scratch,
    }
}

impl Fixture {
    /// One producer commit that rewrites every key, applied to the follower.
    async fn apply_next(&mut self) -> u8 {
        let value = self.next_value;
        self.next_value += 1;
        let base = self.source.latest_commit();
        commit_all(&self.source, value).await;
        let delta_dir = self.scratch.dir();
        self.source
            .snapshot_incremental_to(base, &delta_dir)
            .await
            .unwrap();
        self.follower.apply_incremental(&delta_dir).await.unwrap();
        value
    }

    async fn assert_row_reads_its_value(&self, row: usize) {
        let reader = self
            .follower
            .begin_read_at(self.commits[row])
            .await
            .unwrap();
        for index in 0..KEYS {
            assert_eq!(
                reader.get(&key(index)).await.unwrap().as_deref(),
                Some([self.values[row]; VALUE_LEN].as_slice()),
                "row {row} key {index} left the retained commit"
            );
        }
    }

    async fn assert_row_gone(&self, row: usize) {
        let result = self.follower.begin_read_at(self.commits[row]).await;
        assert!(
            matches!(result, Err(PagedbError::CommitGone { .. })),
            "row {row} still admits a reader, or fails another way"
        );
    }
}

async fn tree_pages<V: crate::vfs::Vfs + Clone>(
    db: &Db<V>,
    roots: [u64; 2],
    next_page_id: u64,
) -> std::collections::BTreeSet<u64> {
    let mut pages = std::collections::BTreeSet::new();
    for root_page_id in roots {
        crate::btree::BTree::open(
            db.pager.clone(),
            db.realm_id,
            root_page_id,
            next_page_id,
            db.page_size,
        )
        .collect_all_page_ids(&mut pages)
        .await
        .unwrap();
    }
    pages
}

async fn pages_at<V: crate::vfs::Vfs + Clone>(
    db: &Db<V>,
    commit: CommitId,
) -> std::collections::BTreeSet<u64> {
    let reader = db.begin_read_at(commit).await.unwrap();
    let roots = [reader.root_page_id(), reader.catalog_root_page_id()];
    let next_page_id = reader.next_page_id();
    drop(reader);
    tree_pages(db, roots, next_page_id).await
}

/// Replace one retained leaf's value with [`OVERWRITTEN`], keeping its kind. The
/// page authenticates afterwards, which is the state an earlier apply left. A real
/// delta page carries the producer's prefix and counter. This one carries that
/// prefix and the local counter.
async fn overwrite_leaf_holding<V: crate::vfs::Vfs + Clone>(
    db: &Db<V>,
    commit: CommitId,
    value: u8,
) -> u64 {
    let needle = [value; VALUE_LEN];
    for page_id in pages_at(db, commit).await {
        let (guard, kind) = db.pager.read_main_node(page_id, REALM).await.unwrap();
        if kind != PageKind::BTreeLeaf {
            continue;
        }
        let mut body = guard.body_ref().to_vec();
        drop(guard);
        let Some(offset) = body
            .windows(VALUE_LEN)
            .position(|window| window == needle.as_slice())
        else {
            continue;
        };
        body[offset..offset + VALUE_LEN].copy_from_slice(&OVERWRITTEN);
        let replaced_prefix = db.pager.swap_to_file_nonce_prefix();
        db.pager
            .write_main_page(page_id, REALM, PageKind::BTreeLeaf, &body)
            .await
            .unwrap();
        db.pager.flush_main(REALM).await.unwrap();
        db.pager.restore_nonce_prefix(replaced_prefix);
        db.pager.reset_main_pages().unwrap();
        return page_id;
    }
    panic!("setup error: no leaf at {commit:?} holds value {value}");
}

/// A reader at the commit gets the overwritten bytes with no error.
async fn assert_row_reads_overwritten_bytes<V: crate::vfs::Vfs + Clone>(
    db: &Db<V>,
    commit: CommitId,
) {
    let reader = db.begin_read_at(commit).await.unwrap();
    let mut found = false;
    for index in 0..KEYS {
        let value = reader.get(&key(index)).await.unwrap();
        found |= value.as_deref() == Some(OVERWRITTEN.as_slice());
    }
    assert!(found, "setup error: no key reads the overwritten bytes");
}

#[tokio::test(flavor = "current_thread")]
async fn an_overwritten_page_prunes_its_row_and_every_older_row_at_the_next_apply() {
    let mut fixture = follower_with_rows(4).await;
    let live_value = fixture.apply_next().await;

    let stale_value = fixture.values[1];
    overwrite_leaf_holding(&fixture.follower, fixture.commits[1], stale_value).await;
    assert_row_reads_overwritten_bytes(&fixture.follower, fixture.commits[1]).await;

    let later_value = fixture.apply_next().await;
    assert_ne!(live_value, later_value);

    fixture.assert_row_gone(0).await;
    fixture.assert_row_gone(1).await;
    fixture.assert_row_reads_its_value(2).await;
    fixture.assert_row_reads_its_value(3).await;
    let reader = fixture.follower.begin_read().await.unwrap();
    assert_eq!(
        reader.get(&key(0)).await.unwrap().as_deref(),
        Some([later_value; VALUE_LEN].as_slice())
    );
    drop(reader);
    let report = run_deep_walk(&fixture.follower).await.unwrap();
    assert!(report.is_clean(), "after the prune: {report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn the_newest_row_is_bounded_by_the_live_root_and_leaves_with_every_older_row() {
    let mut fixture = follower_with_rows(3).await;
    fixture.apply_next().await;

    let stale_value = fixture.values[2];
    overwrite_leaf_holding(&fixture.follower, fixture.commits[2], stale_value).await;
    assert_row_reads_overwritten_bytes(&fixture.follower, fixture.commits[2]).await;

    fixture.apply_next().await;

    for row in 0..3 {
        fixture.assert_row_gone(row).await;
    }
    assert_eq!(
        fixture
            .follower
            .writer
            .lock()
            .await
            .commit_history_root_page_id,
        0,
        "the cut left a history row"
    );
}

/// A row at the live roots has no later root, so nothing bounds it. This pins a
/// stated limit: an overwrite there stays undetected until the roots move.
#[tokio::test(flavor = "current_thread")]
async fn a_row_at_the_live_roots_has_no_bound_and_its_overwrite_stays_undetected() {
    let fixture = follower_with_rows(2).await;
    let stale_value = fixture.values[1];
    overwrite_leaf_holding(&fixture.follower, fixture.commits[1], stale_value).await;

    let report = run_deep_walk(&fixture.follower).await.unwrap();

    assert_eq!(report.history_seal_verdict, HistorySealVerdict::Compared);
    assert!(report.stale_history_rows.is_empty(), "{report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_deep_walk_names_the_stale_row_and_changes_nothing() {
    let mut fixture = follower_with_rows(4).await;
    fixture.apply_next().await;
    let stale_value = fixture.values[1];
    let page_id = overwrite_leaf_holding(&fixture.follower, fixture.commits[1], stale_value).await;
    let history_root = fixture
        .follower
        .writer
        .lock()
        .await
        .commit_history_root_page_id;

    let report = run_deep_walk(&fixture.follower).await.unwrap();

    assert!(!report.is_clean(), "the stale row must fail the walk");
    assert_eq!(report.history_seal_verdict, HistorySealVerdict::Compared);
    assert_eq!(report.stale_history_rows.len(), 1, "{report:?}");
    let stale = &report.stale_history_rows[0];
    assert_eq!(stale.commit, fixture.commits[1]);
    assert!(
        matches!(
            stale.evidence,
            StaleRowEvidence::SealedAfterLaterRoot { page_id: found, .. } if found == page_id
        ),
        "{stale:?}"
    );
    let mut text = Vec::new();
    report.write_text(&mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("stale commit-history rows (1)")
    );

    assert_eq!(
        fixture
            .follower
            .writer
            .lock()
            .await
            .commit_history_root_page_id,
        history_root,
        "the walk moved the history"
    );
    assert_row_reads_overwritten_bytes(&fixture.follower, fixture.commits[1]).await;
    fixture.assert_row_reads_its_value(0).await;
}

/// The path `pagedb-fsck --deep` takes, with no follower left running.
#[tokio::test(flavor = "current_thread")]
async fn a_deep_walk_on_a_read_only_handle_reports_the_stale_row() {
    let scratch = Scratch::new();
    let source = open_source(&scratch.dir(), unbounded()).await;
    let mut commits = Vec::new();
    for value in 1..=3 {
        commits.push(commit_all(&source, value).await);
    }
    let snap_dir = scratch.dir();
    source.snapshot_to(&snap_dir).await.unwrap();
    let dst_dir = scratch.dir();
    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &dst_dir, OpenOptions::default(), KEK)
        .await
        .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    overwrite_leaf_holding(&follower, commits[0], 1).await;
    drop(follower);

    let read_only = Db::<TokioVfs>::open_read_only(
        TokioVfs::new(&dst_dir),
        KEK,
        PAGE,
        REALM,
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let report = run_deep_walk(&read_only).await.unwrap();
    assert_eq!(report.stale_history_rows.len(), 1, "{report:?}");
    assert_eq!(report.stale_history_rows[0].commit, commits[0]);
}

/// A rekey reseals in walk order, so its counters order nothing. An overwrite
/// after it stays undetected, and the check prunes nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_rekeyed_store_reports_inconclusive_and_the_check_prunes_nothing() {
    let scratch = Scratch::new();
    let db = open_source(&scratch.dir(), unbounded()).await;
    let mut commits = Vec::new();
    for value in 1..=4 {
        commits.push(commit_all(&db, value).await);
    }
    db.rekey_db(KEK, 1).await.unwrap();
    overwrite_leaf_holding(&db, commits[1], 2).await;

    let report = run_deep_walk(&db).await.unwrap();
    assert_eq!(
        report.history_seal_verdict,
        HistorySealVerdict::Inconclusive(SealOrderVoid::RekeyedEpoch)
    );
    assert!(report.stale_history_rows.is_empty(), "{report:?}");

    db.rekey_db(KEK, 2).await.unwrap();

    assert_row_reads_overwritten_bytes(&db, commits[1]).await;
    assert!(db.begin_read_at(commits[0]).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn a_follower_restored_from_a_rekeyed_store_prunes_nothing_from_the_check() {
    let scratch = Scratch::new();
    let source = open_source(&scratch.dir(), unbounded()).await;
    let mut commits = Vec::new();
    for value in 1..=3 {
        commits.push(commit_all(&source, value).await);
    }
    source.rekey_db(KEK, 1).await.unwrap();
    let snap_dir = scratch.dir();
    source.snapshot_to(&snap_dir).await.unwrap();
    let restored =
        Db::<TokioVfs>::restore_from(&snap_dir, &scratch.dir(), OpenOptions::default(), KEK)
            .await
            .unwrap();
    let follower = restored.promote_to_follower().await.unwrap();
    overwrite_leaf_holding(&follower, commits[0], 1).await;

    let base = source.latest_commit();
    commit_all(&source, 9).await;
    let delta_dir = scratch.dir();
    source
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .unwrap();
    follower.apply_incremental(&delta_dir).await.unwrap();

    assert_row_reads_overwritten_bytes(&follower, commits[0]).await;
}

/// The `PlaintextMac` tag does not cover the nonce, so a counter is unproved.
#[tokio::test(flavor = "current_thread")]
async fn a_plaintext_mac_store_reports_inconclusive() {
    let scratch = Scratch::new();
    let db = open_source(
        &scratch.dir(),
        unbounded().with_cipher(CipherId::PlaintextMac),
    )
    .await;
    for value in 1..=2 {
        commit_all(&db, value).await;
    }
    let report = run_deep_walk(&db).await.unwrap();
    assert_eq!(
        report.history_seal_verdict,
        HistorySealVerdict::Inconclusive(SealOrderVoid::UnauthenticatedNonce)
    );
    assert!(report.stale_history_rows.is_empty(), "{report:?}");
}

/// Copy a closed store's directory file by file, outside the API.
fn byte_copy(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            byte_copy(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

async fn open_copy_as_follower(dir: &std::path::Path) -> Db<TokioVfs> {
    Db::open_follower(TokioVfs::new(dir), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap()
}

/// A source with one commit, closed, copied, and reopened. Returns the copy's path.
async fn source_and_byte_copy(scratch: &Scratch) -> (Db<TokioVfs>, std::path::PathBuf) {
    let source_dir = scratch.dir();
    let source = open_source(&source_dir, unbounded()).await;
    commit_all(&source, 1).await;
    drop(source);
    let copy_dir = scratch.dir();
    byte_copy(&source_dir, &copy_dir);
    (open_source(&source_dir, unbounded()).await, copy_dir)
}

/// Two writers on one identity repeat nonces and mix counter streams. The stamp
/// stops the copy becoming the second writer. A fork still gives it a way out.
#[tokio::test(flavor = "current_thread")]
async fn a_byte_copy_applied_to_as_a_follower_refuses_standalone() {
    let scratch = Scratch::new();
    let (source, copy_dir) = source_and_byte_copy(&scratch).await;
    let base = source.latest_commit();
    let target = commit_all(&source, 2).await;
    let delta_dir = scratch.dir();
    source
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .unwrap();

    let follower = open_copy_as_follower(&copy_dir).await;
    follower.apply_incremental(&delta_dir).await.unwrap();
    assert_eq!(follower.latest_commit(), target);
    drop(follower);

    let standalone = Db::open(
        TokioVfs::new(&copy_dir),
        KEK,
        PAGE,
        REALM,
        OpenOptions::default(),
    )
    .await;
    assert!(matches!(standalone, Err(PagedbError::RestoredNotPromoted)));

    let follower = open_copy_as_follower(&copy_dir).await;
    assert_eq!(follower.latest_commit(), target);
    let writer = follower.rekey_into_writer(KEK).await.unwrap();
    assert_eq!(writer.mode(), DbMode::Standalone);
    let reader = writer.begin_read().await.unwrap();
    assert_eq!(
        reader.get(&key(0)).await.unwrap().as_deref(),
        Some([2u8; VALUE_LEN].as_slice())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_byte_copy_opened_as_a_follower_with_no_apply_keeps_opening_standalone() {
    let scratch = Scratch::new();
    let (_source, copy_dir) = source_and_byte_copy(&scratch).await;
    drop(open_copy_as_follower(&copy_dir).await);

    let standalone = Db::open(
        TokioVfs::new(&copy_dir),
        KEK,
        PAGE,
        REALM,
        OpenOptions::default(),
    )
    .await;
    assert!(standalone.is_ok(), "a follower open alone stamps nothing");
}

/// The delta's base is not the copy's commit, so the manifest check refuses it
/// before the stamp. A refused delta must not cost the store its writer.
#[tokio::test(flavor = "current_thread")]
async fn an_apply_refused_by_its_manifest_leaves_a_byte_copy_able_to_open_standalone() {
    let scratch = Scratch::new();
    let (source, copy_dir) = source_and_byte_copy(&scratch).await;
    let base = commit_all(&source, 2).await;
    commit_all(&source, 3).await;
    let delta_dir = scratch.dir();
    source
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .unwrap();

    let follower = open_copy_as_follower(&copy_dir).await;
    assert!(follower.apply_incremental(&delta_dir).await.is_err());
    drop(follower);

    let standalone = Db::open(
        TokioVfs::new(&copy_dir),
        KEK,
        PAGE,
        REALM,
        OpenOptions::default(),
    )
    .await;
    assert!(standalone.is_ok(), "a refused delta stamped the store");
}

struct Random(u64);

impl Random {
    fn step(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: u64) -> u64 {
        self.step() % limit
    }
}

type Model = BTreeMap<Vec<u8>, Vec<u8>>;

/// Puts, overwrites, deletes, and values long enough to overflow.
async fn random_commit(db: &Db<TokioVfs>, random: &mut Random, model: &mut Model) -> CommitId {
    let mut write = db.begin_write().await.unwrap();
    for _ in 0..(1 + random.below(40)) {
        let name = key(u32::try_from(random.below(300)).unwrap());
        match random.below(6) {
            0 => {
                write.delete(&name).await.unwrap();
                model.remove(&name);
            }
            1 => {
                let value = vec![random.below(256) as u8; PAGE * 2];
                write.put(&name, &value).await.unwrap();
                model.insert(name, value);
            }
            _ => {
                let value = vec![random.below(256) as u8; 1 + random.below(200) as usize];
                write.put(&name, &value).await.unwrap();
                model.insert(name, value);
            }
        }
    }
    write.commit().await.unwrap()
}

async fn assert_commit_reads_model<V: crate::vfs::Vfs + Clone>(
    db: &Db<V>,
    commit: CommitId,
    model: &Model,
) {
    let reader = db.begin_read_at(commit).await.unwrap();
    for (name, value) in model {
        assert_eq!(
            reader.get(name).await.unwrap().as_deref(),
            Some(value.as_slice()),
            "{commit:?} lost its value"
        );
    }
}

/// The seal check must find nothing on a store no one damaged. A false positive
/// here is a durable loss of a good row.
async fn assert_no_stale_rows<V: crate::vfs::Vfs + Clone>(db: &Db<V>, context: &str) {
    let report = run_deep_walk(db).await.unwrap();
    assert!(
        report.stale_history_rows.is_empty(),
        "{context}: an intact store reports stale rows: {report:?}"
    );
}

/// One run: a producer with restarts and an optional compaction, then a follower
/// with applies and restarts. `Unbounded` recycles no retained page, so every row
/// must survive. `Count` recycles them, so a row can leave through a real delta
/// overlap, and each row that stays must still read its own values.
async fn run_clean_follower(seed: u64, retain: RetainPolicy, compact: bool) {
    let every_row_stays = matches!(retain, RetainPolicy::Unbounded);
    let source_options = || {
        OpenOptions::default()
            .with_commit_history_retain(retain.clone())
            .with_anchor_budget(16)
            .with_buffer_pool_pages(32)
    };
    let mut random = Random(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let scratch = Scratch::new();
    let source_dir = scratch.dir();
    let mut source = open_source(&source_dir, source_options()).await;
    let mut model = Model::new();

    for _ in 0..(4 + random.below(4)) {
        random_commit(&source, &mut random, &mut model).await;
    }
    if compact {
        source.compact_now().await.unwrap();
    }
    let mut rows = Vec::new();
    for _ in 0..(3 + random.below(4)) {
        let commit = random_commit(&source, &mut random, &mut model).await;
        rows.push((commit, model.clone()));
        if random.below(3) == 0 {
            drop(source);
            source = open_source(&source_dir, source_options()).await;
        }
    }
    assert_no_stale_rows(&source, "producer").await;

    let snap_dir = scratch.dir();
    source.snapshot_to(&snap_dir).await.unwrap();
    let follower_dir = scratch.dir();
    let follower_options = || {
        OpenOptions::default()
            .with_anchor_budget(16)
            .with_buffer_pool_pages(32)
    };
    let restored = Db::<TokioVfs>::restore_from(&snap_dir, &follower_dir, follower_options(), KEK)
        .await
        .unwrap();
    let mut follower = restored.promote_to_follower().await.unwrap();

    for round in 0..(4 + random.below(4)) {
        let base = source.latest_commit();
        // A bounded policy can prune `base` past one commit, and the export then
        // reports `CommitGone`. That says nothing about the follower's rows.
        let commits = if every_row_stays {
            1 + random.below(3)
        } else {
            1
        };
        for _ in 0..commits {
            random_commit(&source, &mut random, &mut model).await;
        }
        let delta_dir = scratch.dir();
        source
            .snapshot_incremental_to(base, &delta_dir)
            .await
            .unwrap();
        follower.apply_incremental(&delta_dir).await.unwrap();
        assert_no_stale_rows(&follower, &format!("seed {seed} round {round}")).await;

        if random.below(3) == 0 {
            drop(follower);
            follower = Db::open_follower(
                TokioVfs::new(&follower_dir),
                KEK,
                PAGE,
                REALM,
                follower_options(),
            )
            .await
            .unwrap();
        }
        if random.below(3) == 0 {
            drop(source);
            source = open_source(&source_dir, source_options()).await;
        }
    }

    for (commit, expected) in &rows {
        match follower.begin_read_at(*commit).await {
            Ok(reader) => {
                drop(reader);
                assert_commit_reads_model(&follower, *commit, expected).await;
            }
            Err(PagedbError::CommitGone { .. }) => assert!(
                !every_row_stays,
                "seed {seed}: {commit:?} left a store that recycled no retained page"
            ),
            Err(error) => panic!("seed {seed}: {commit:?} failed: {error:?}"),
        }
    }
    let report = run_deep_walk(&follower).await.unwrap();
    assert!(report.is_clean(), "seed {seed}: {report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_clean_follower_with_a_retaining_producer_never_loses_a_row() {
    for seed in 1..=8 {
        run_clean_follower(seed, RetainPolicy::Unbounded, false).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_clean_follower_of_a_compacted_producer_never_loses_a_row() {
    for seed in 9..=16 {
        run_clean_follower(seed, RetainPolicy::Unbounded, true).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_clean_follower_of_a_recycling_producer_keeps_each_row_correct() {
    for seed in 17..=24 {
        run_clean_follower(seed, RetainPolicy::Count(2), seed % 2 == 0).await;
    }
}
