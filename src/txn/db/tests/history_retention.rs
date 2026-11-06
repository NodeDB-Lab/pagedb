//! `RetainPolicy::Disabled` means no rows, and a header can prove rows are gone.

use std::sync::atomic::Ordering;

use crate::options::{OpenOptions, RetainPolicy};
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::recovery::deep_walk::run_deep_walk;
use crate::vfs::memory::MemVfs;
use crate::vfs::{OpenMode, Vfs, VfsFile};
use crate::{CommitId, Db, PagedbError, RealmId, RealmQuotas};

use super::super::catalog::history_policy::RETAIN_POLICY_TAG_DISABLED;

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0xC7; 32];
const REALM: RealmId = RealmId::new([0xC8; 16]);

fn retaining(policy: RetainPolicy) -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(policy)
}

fn count_2() -> OpenOptions {
    retaining(RetainPolicy::Count(2))
}

fn disabled() -> OpenOptions {
    retaining(RetainPolicy::Disabled)
}

async fn reopen(vfs: &MemVfs, options: OpenOptions) -> Db<MemVfs> {
    Db::open_existing_with_options(vfs.clone(), KEK, PAGE, REALM, options)
        .await
        .unwrap()
}

async fn commit_value<V: Vfs + Clone>(db: &Db<V>, value: &[u8]) -> CommitId {
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"versioned", value).await.unwrap();
    txn.commit().await.unwrap()
}

/// A closed Count(2) store holding rows for its two commits.
async fn store_with_two_rows() -> (MemVfs, CommitId, CommitId) {
    let vfs = MemVfs::new();
    let db = Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, count_2())
        .await
        .unwrap();
    let first = commit_value(&db, b"first").await;
    let second = commit_value(&db, b"second").await;
    (vfs, first, second)
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

async fn assert_reads<V: Vfs + Clone>(db: &Db<V>, commit: CommitId, value: &[u8]) {
    let reader = db
        .begin_read_at(commit)
        .await
        .unwrap_or_else(|error| panic!("{commit:?} refused a reader: {error:?}"));
    assert_eq!(
        reader.get(b"versioned").await.unwrap().as_deref(),
        Some(value),
        "{commit:?} holds another value"
    );
}

async fn assert_clean<V: Vfs + Clone>(db: &Db<V>) {
    let report = run_deep_walk(db).await.unwrap();
    assert!(report.is_clean(), "deep walk report: {report:?}");
}

async fn history_root<V: Vfs + Clone>(db: &Db<V>) -> u64 {
    db.writer.lock().await.commit_history_root_page_id
}

async fn main_db_bytes(vfs: &MemVfs) -> Vec<u8> {
    let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    let length = usize::try_from(file.len().await.unwrap()).unwrap();
    let mut bytes = vec![0u8; length];
    let read = file.read_at(0, &mut bytes).await.unwrap();
    assert_eq!(read, length);
    bytes
}

async fn store_with_abandoned_rows() -> (MemVfs, CommitId, CommitId) {
    let (vfs, first, second) = store_with_two_rows().await;
    mark_rows_abandoned(&vfs).await;
    (vfs, first, second)
}

/// Rewrite the header as a release that kept the root under `Disabled` left it.
/// That release wrote tag 3 beside a non-zero root. This build writes no such pair.
async fn mark_rows_abandoned(vfs: &MemVfs) {
    let db = reopen(vfs, count_2()).await;
    let mut state = db.writer.lock().await;
    state.commit_retain_policy_tag = RETAIN_POLICY_TAG_DISABLED;
    state.commit_retain_policy_value = 0;
    assert_ne!(state.commit_history_root_page_id, 0);
    let cursor = db.pager.header_cursor().unwrap();
    let seq = cursor.next_seq().unwrap();
    let anchor = db.pager.pending_anchor();
    let fields = db.state_header_fields(&state, seq, anchor).unwrap();
    let hk = db.hk.read().clone();
    let slot = commit_header(
        &*db.vfs,
        &db.main_db_path,
        &hk,
        &fields,
        cursor.slot,
        db.page_size,
    )
    .await
    .unwrap();
    db.pager.note_header_written(HeaderCursor { slot, seq });
    db.pager.commit_anchor(anchor).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_disabled_handle_serves_the_latest_commit_and_its_first_commit_removes_the_rows() {
    let (vfs, first, second) = store_with_two_rows().await;

    let db = reopen(&vfs, disabled()).await;
    assert_gone(&db, first, second).await;
    assert_reads(&db, second, b"second").await;
    assert_ne!(history_root(&db).await, 0, "only a commit removes the rows");

    let third = commit_value(&db, b"third").await;

    assert_eq!(history_root(&db).await, 0);
    assert_gone(&db, first, third).await;
    assert_gone(&db, second, third).await;
    assert_reads(&db, third, b"third").await;
    assert_clean(&db).await;
    // The next commit draws from pages the rows held back, and stays clean.
    let fourth = commit_value(&db, &vec![0xAB; PAGE * 3]).await;
    assert_clean(&db).await;
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    assert_eq!(history_root(&db).await, 0);
    assert_gone(&db, first, fourth).await;
    assert_gone(&db, third, fourth).await;
    assert_clean(&db).await;
}

/// The removed rows stay gone across a later policy and a rekey. Rows the later
/// policy writes read back.
#[tokio::test(flavor = "current_thread")]
async fn rows_a_disabled_commit_removed_stay_gone_across_a_later_policy_and_a_rekey() {
    let (vfs, first, second) = store_with_two_rows().await;
    let db = reopen(&vfs, disabled()).await;
    let third = commit_value(&db, b"third").await;
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    let fourth = commit_value(&db, b"fourth").await;
    let fifth = commit_value(&db, b"fifth").await;
    db.rekey_db(KEK, 1).await.unwrap();
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    for commit in [first, second, third] {
        assert_gone(&db, commit, fourth).await;
    }
    assert_reads(&db, fourth, b"fourth").await;
    assert_reads(&db, fifth, b"fifth").await;
    assert_clean(&db).await;
}

/// A rekey walks the rows. A `Disabled` handle owes them nothing, so it removes
/// them first, and a later policy finds them gone.
#[tokio::test(flavor = "current_thread")]
async fn a_rekey_on_a_disabled_handle_removes_the_rows_before_its_first_commit() {
    let (vfs, first, second) = store_with_two_rows().await;
    let db = reopen(&vfs, disabled()).await;

    db.rekey_db(KEK, 1).await.unwrap();

    assert_eq!(history_root(&db).await, 0);
    drop(db);
    let db = reopen(&vfs, count_2()).await;
    assert_gone(&db, first, second).await;
    assert_reads(&db, second, b"second").await;
    assert_clean(&db).await;
}

/// The old header stays durable until the commit's header lands, and the commit
/// writes pages before that. Until then the rows still bound reuse.
#[tokio::test(flavor = "current_thread")]
async fn a_disabled_handle_draws_no_page_a_row_reaches_before_it_removes_the_rows() {
    let vfs = MemVfs::new();
    let options = retaining(RetainPolicy::Count(8));
    let db = Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, options)
        .await
        .unwrap();
    let first = commit_value(&db, b"first").await;
    commit_value(&db, b"second").await;
    commit_value(&db, b"third").await;
    let first_root = db.begin_read_at(first).await.unwrap().root_page_id();
    drop(db);

    let db = reopen(&vfs, disabled()).await;
    let txn = db.begin_write().await.unwrap();
    let cache = db.free_page_cache.lock().clone();
    txn.abort().await;
    assert!(
        !cache.contains(&first_root),
        "page {first_root} of the row at {first:?} reached the allocator {cache:?}"
    );
    drop(db);

    let db = reopen(&vfs, retaining(RetainPolicy::Count(8))).await;
    assert_reads(&db, first, b"first").await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_read_only_disabled_handle_refuses_old_commits_and_changes_nothing() {
    let (vfs, first, second) = store_with_two_rows().await;
    let before = main_db_bytes(&vfs).await;

    // The handle `pagedb-fsck` opens.
    let db = Db::open_read_only(vfs.clone(), KEK, PAGE, REALM, disabled())
        .await
        .unwrap();
    assert_gone(&db, first, second).await;
    assert_reads(&db, second, b"second").await;
    assert_ne!(history_root(&db).await, 0);
    assert_clean(&db).await;
    drop(db);

    let observer = Db::open_observer(vfs.clone(), KEK, PAGE, REALM, disabled())
        .await
        .unwrap();
    assert_gone(&observer, first, second).await;
    assert_reads(&observer, second, b"second").await;
    drop(observer);

    assert_eq!(main_db_bytes(&vfs).await, before, "main.db changed");
    let db = reopen(&vfs, count_2()).await;
    assert_reads(&db, first, b"first").await;
    assert_reads(&db, second, b"second").await;
}

/// Tag 3 beside a root is gone under every policy. A read-only handle reports
/// that and writes nothing. A writable handle removes the rows at its first commit.
#[tokio::test(flavor = "current_thread")]
async fn a_header_proving_abandoned_rows_makes_them_gone_under_count() {
    let (vfs, first, second) = store_with_abandoned_rows().await;
    let before = main_db_bytes(&vfs).await;

    let db = Db::open_read_only(vfs.clone(), KEK, PAGE, REALM, count_2())
        .await
        .unwrap();
    assert_gone(&db, first, second).await;
    assert_clean(&db).await;
    drop(db);
    let fsck = Db::open_read_only(vfs.clone(), KEK, PAGE, REALM, disabled())
        .await
        .unwrap();
    assert_clean(&fsck).await;
    drop(fsck);
    assert_eq!(main_db_bytes(&vfs).await, before, "main.db changed");

    let db = reopen(&vfs, count_2()).await;
    assert_gone(&db, first, second).await;
    let abandoned_root = history_root(&db).await;
    assert_ne!(abandoned_root, 0, "only a commit removes the rows");

    let third = commit_value(&db, b"third").await;

    assert_gone(&db, first, third).await;
    assert_gone(&db, second, third).await;
    assert_reads(&db, third, b"third").await;
    assert_ne!(history_root(&db).await, abandoned_root);
    assert_clean(&db).await;
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    assert_gone(&db, second, third).await;
    assert_reads(&db, third, b"third").await;
}

/// A header that is not a commit repeats the tag, so the proof survives it.
#[tokio::test(flavor = "current_thread")]
async fn a_quota_header_keeps_the_proof_of_abandoned_rows() {
    let (vfs, first, second) = store_with_abandoned_rows().await;
    let db = reopen(&vfs, count_2()).await;

    db.set_realm_quotas(
        REALM,
        RealmQuotas {
            max_pages: Some(1000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    assert_gone(&db, first, second).await;
}

/// A rekey removes abandoned rows first. One of them names a torn page, which
/// must stop neither the rekey nor the reopen.
#[tokio::test(flavor = "current_thread")]
async fn a_rekey_removes_abandoned_rows_without_walking_them() {
    let (vfs, first, second) = store_with_two_rows().await;
    let db = reopen(&vfs, count_2()).await;
    let stale_root = db.begin_read_at(first).await.unwrap().root_page_id();
    drop(db);
    mark_rows_abandoned(&vfs).await;
    let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    let torn_offset = stale_root * PAGE as u64 + (PAGE / 2) as u64;
    file.write_at(torn_offset, &[0xEE; PAGE / 2]).await.unwrap();
    file.sync().await.unwrap();
    drop(file);

    let db = reopen(&vfs, count_2()).await;
    db.rekey_db(KEK, 1).await.unwrap();
    assert_eq!(history_root(&db).await, 0);
    assert_eq!(db.mk_epoch.load(Ordering::SeqCst), 1);
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    assert_gone(&db, first, second).await;
    assert_reads(&db, second, b"second").await;
    assert_clean(&db).await;
}

/// `state` kept the open-time tag. A later header then named a live tree under
/// tag 3. That pair marks maintained rows as abandoned at the next open.
#[tokio::test(flavor = "current_thread")]
async fn a_quota_header_after_a_count_commit_does_not_mark_its_rows_abandoned() {
    let vfs = MemVfs::new();
    let db = Db::open_internal_with_options(vfs.clone(), KEK, PAGE, REALM, disabled())
        .await
        .unwrap();
    commit_value(&db, b"disabled").await;
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    assert_eq!(
        db.writer.lock().await.commit_retain_policy_tag,
        RETAIN_POLICY_TAG_DISABLED
    );
    let kept = commit_value(&db, b"kept").await;
    db.set_realm_quotas(
        REALM,
        RealmQuotas {
            max_pages: Some(1000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    let newer = commit_value(&db, b"newer").await;
    db.set_realm_quotas(
        REALM,
        RealmQuotas {
            max_pages: Some(2000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    assert_reads(&db, kept, b"kept").await;
    assert_reads(&db, newer, b"newer").await;
}

/// A later header must report what the handle did, not what it found at open.
#[tokio::test(flavor = "current_thread")]
async fn a_quota_header_after_a_disabled_commit_writes_the_disabled_tag() {
    let (vfs, _first, _second) = store_with_two_rows().await;
    let db = reopen(&vfs, disabled()).await;
    commit_value(&db, b"third").await;
    db.set_realm_quotas(
        REALM,
        RealmQuotas {
            max_pages: Some(1000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    drop(db);

    let db = reopen(&vfs, count_2()).await;
    let state = db.writer.lock().await;
    assert_eq!(state.commit_retain_policy_tag, RETAIN_POLICY_TAG_DISABLED);
    assert_eq!(state.commit_history_root_page_id, 0);
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn an_incremental_export_from_a_disabled_handle_reports_an_old_base_gone() {
    let (vfs, first, second) = store_with_two_rows().await;
    let db = reopen(&vfs, disabled()).await;

    let outcome = db
        .snapshot_incremental_to(first, std::path::Path::new("/unused"))
        .await;

    assert!(
        matches!(
            outcome,
            Err(PagedbError::CommitGone { commit, oldest_available })
                if commit == first && oldest_available == second
        ),
        "got {outcome:?}"
    );
}

/// An apply needs a backend with a root path, so this test uses `TokioVfs`.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn a_disabled_follower_publishes_root_zero_at_its_first_apply() {
    use crate::vfs::tokio_backend::TokioVfs;

    let [src_dir, snap_dir, dst_dir, delta_dir] =
        std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let source = Db::open(
        TokioVfs::new(src_dir.path()),
        KEK,
        PAGE,
        REALM,
        retaining(RetainPolicy::Count(8)),
    )
    .await
    .unwrap();
    let first = commit_value(&source, b"first").await;
    let base = commit_value(&source, b"base").await;
    source.snapshot_to(snap_dir.path()).await.unwrap();
    let target = commit_value(&source, b"target").await;
    source
        .snapshot_incremental_to(base, delta_dir.path())
        .await
        .unwrap();
    drop(source);

    let follower = Db::<TokioVfs>::restore_from(snap_dir.path(), dst_dir.path(), disabled(), KEK)
        .await
        .unwrap()
        .promote_to_follower()
        .await
        .unwrap();
    assert_ne!(history_root(&follower).await, 0, "setup error: no rows");
    assert_gone(&follower, first, base).await;
    assert_reads(&follower, base, b"base").await;

    follower.apply_incremental(delta_dir.path()).await.unwrap();

    assert_eq!(follower.latest_commit(), target);
    assert_eq!(history_root(&follower).await, 0);
    assert_gone(&follower, base, target).await;
    assert_reads(&follower, target, b"target").await;
    assert_clean(&follower).await;
    drop(follower);

    let follower = Db::open_follower(
        TokioVfs::new(dst_dir.path()),
        KEK,
        PAGE,
        REALM,
        retaining(RetainPolicy::Count(8)),
    )
    .await
    .unwrap();
    assert_eq!(history_root(&follower).await, 0);
    assert_gone(&follower, base, target).await;
}
