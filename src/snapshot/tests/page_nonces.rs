//! Page nonces of followers and their producer, read as raw envelope bytes from
//! each `main.db`.

use std::path::{Path, PathBuf};

use crate::pager::PageKind;
use crate::pager::page_nonce_ledger::PageNonceLedger;
use crate::vfs::tokio_backend::TokioVfs;
use crate::{CommitId, Db, HistorySealVerdict, OpenOptions, run_deep_walk};

use super::stale_history::{
    KEK, PAGE, REALM, Scratch, VALUE_LEN, commit_all, key, open_source, unbounded,
};

const BUDGET: u64 = 16;

fn budgeted() -> OpenOptions {
    OpenOptions::default().with_anchor_budget(BUDGET)
}

fn source_options() -> OpenOptions {
    unbounded().with_anchor_budget(BUDGET)
}

fn record(ledger: &mut PageNonceLedger, dir: &Path) {
    let image = std::fs::read(dir.join("main.db")).unwrap();
    ledger.record_image(&image, PAGE);
}

/// The 6-byte prefix and the counter in the raw envelope of `page_id`.
fn raw_seal(dir: &Path, page_id: u64) -> ([u8; 6], u64) {
    let image = std::fs::read(dir.join("main.db")).unwrap();
    let start = usize::try_from(page_id).unwrap() * PAGE;
    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&image[start + 12..start + 18]);
    let mut counter = [0u8; 8];
    counter[..6].copy_from_slice(&image[start + 18..start + 24]);
    (prefix, u64::from_le_bytes(counter))
}

fn raw_kind(dir: &Path, page_id: u64) -> u8 {
    let image = std::fs::read(dir.join("main.db")).unwrap();
    image[usize::try_from(page_id).unwrap() * PAGE + 1]
}

fn file_prefix(db: &Db<TokioVfs>) -> [u8; 6] {
    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&db.file_id[..6]);
    prefix
}

/// A producer with two retained commits, and a snapshot of it.
async fn producer_with_snapshot(scratch: &Scratch) -> (Db<TokioVfs>, PathBuf, PathBuf) {
    let source_dir = scratch.dir();
    let source = open_source(&source_dir, source_options()).await;
    commit_all(&source, 1).await;
    commit_all(&source, 2).await;
    let snap_dir = scratch.dir();
    source.snapshot_to(&snap_dir).await.unwrap();
    (source, source_dir, snap_dir)
}

async fn follower_from(scratch: &Scratch, snap_dir: &Path) -> (Db<TokioVfs>, PathBuf) {
    let dir = scratch.dir();
    let restored = Db::<TokioVfs>::restore_from(snap_dir, &dir, budgeted(), KEK)
        .await
        .unwrap();
    (restored.promote_to_follower().await.unwrap(), dir)
}

/// One producer commit that rewrites a single key.
async fn overwrite_one_key(source: &Db<TokioVfs>, value: u8) {
    let mut write = source.begin_write().await.unwrap();
    write.put(&key(0), &[value; VALUE_LEN]).await.unwrap();
    write.commit().await.unwrap();
}

async fn apply_since(
    scratch: &Scratch,
    source: &Db<TokioVfs>,
    base: CommitId,
    follower: &Db<TokioVfs>,
) {
    let delta_dir = scratch.dir();
    source
        .snapshot_incremental_to(base, &delta_dir)
        .await
        .unwrap();
    follower.apply_incremental(&delta_dir).await.unwrap();
}

/// The head of the follower's free-list chain. The apply wrote it locally.
async fn chain_head(follower: &Db<TokioVfs>) -> u64 {
    let head = follower.writer.lock().await.free_list_root_page_id;
    assert_ne!(head, 0, "setup error: the apply wrote no free-list chain");
    head
}

#[tokio::test(flavor = "current_thread")]
async fn page_nonces_stay_distinct_between_a_follower_and_its_producer() {
    let scratch = Scratch::new();
    let (source, source_dir, snap_dir) = producer_with_snapshot(&scratch).await;
    let (follower, follower_dir) = follower_from(&scratch, &snap_dir).await;
    let mut ledger = PageNonceLedger::default();
    record(&mut ledger, &source_dir);
    record(&mut ledger, &follower_dir);

    let base = source.latest_commit();
    overwrite_one_key(&source, 3).await;
    apply_since(&scratch, &source, base, &follower).await;
    chain_head(&follower).await;
    record(&mut ledger, &source_dir);
    record(&mut ledger, &follower_dir);

    let base = source.latest_commit();
    let start = source.pager.pending_anchor();
    let mut value = 4;
    while source.pager.pending_anchor() < start + 2 * BUDGET {
        commit_all(&source, value).await;
        value += 1;
        record(&mut ledger, &source_dir);
    }
    apply_since(&scratch, &source, base, &follower).await;
    record(&mut ledger, &source_dir);
    record(&mut ledger, &follower_dir);

    ledger.assert_page_nonces_are_distinct("follower and producer");
}

/// Both followers start from one anchor, and each takes a different delta. Their
/// chain pages therefore hold different plaintext at the same counters.
#[tokio::test(flavor = "current_thread")]
async fn page_nonces_stay_distinct_between_two_followers_of_one_snapshot() {
    let scratch = Scratch::new();
    let (source, _source_dir, snap_dir) = producer_with_snapshot(&scratch).await;
    let (first, first_dir) = follower_from(&scratch, &snap_dir).await;
    let (second, second_dir) = follower_from(&scratch, &snap_dir).await;
    let base = source.latest_commit();

    overwrite_one_key(&source, 3).await;
    apply_since(&scratch, &source, base, &first).await;
    commit_all(&source, 4).await;
    apply_since(&scratch, &source, base, &second).await;
    chain_head(&first).await;
    chain_head(&second).await;

    let mut ledger = PageNonceLedger::default();
    record(&mut ledger, &first_dir);
    record(&mut ledger, &second_dir);
    ledger.assert_page_nonces_are_distinct("two followers");
}

/// Local pages stay off every row walk, so they leave the seal scan conclusive.
/// Delta pages keep the producer's prefix, and local pages take another one.
#[tokio::test(flavor = "current_thread")]
async fn a_clean_follower_with_local_chain_pages_reports_a_conclusive_verdict() {
    let scratch = Scratch::new();
    let (source, _source_dir, snap_dir) = producer_with_snapshot(&scratch).await;
    let (follower, follower_dir) = follower_from(&scratch, &snap_dir).await;
    let base = source.latest_commit();
    overwrite_one_key(&source, 3).await;
    apply_since(&scratch, &source, base, &follower).await;

    let head = chain_head(&follower).await;
    assert_eq!(raw_kind(&follower_dir, head), PageKind::Free.as_byte());
    assert_ne!(raw_seal(&follower_dir, head).0, file_prefix(&follower));
    let root = follower.writer.lock().await.root_page_id;
    assert_eq!(raw_seal(&follower_dir, root).0, file_prefix(&follower));

    let report = run_deep_walk(&follower).await.unwrap();
    assert_eq!(report.history_seal_verdict, HistorySealVerdict::Compared);
    assert!(report.is_clean(), "{report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_followers_local_pages_stay_readable_across_a_restart_under_a_new_prefix() {
    let scratch = Scratch::new();
    let (source, _source_dir, snap_dir) = producer_with_snapshot(&scratch).await;
    let (follower, follower_dir) = follower_from(&scratch, &snap_dir).await;
    let base = source.latest_commit();
    overwrite_one_key(&source, 3).await;
    apply_since(&scratch, &source, base, &follower).await;
    let head = chain_head(&follower).await;
    let (first_prefix, first_counter) = raw_seal(&follower_dir, head);
    let file = file_prefix(&follower);
    drop(follower);

    let reopened = Db::open_follower(TokioVfs::new(&follower_dir), KEK, PAGE, REALM, budgeted())
        .await
        .unwrap();
    assert_eq!(chain_head(&reopened).await, head);
    let report = run_deep_walk(&reopened).await.unwrap();
    assert!(report.is_clean(), "{report:?}");

    let base = source.latest_commit();
    overwrite_one_key(&source, 4).await;
    apply_since(&scratch, &source, base, &reopened).await;

    let (second_prefix, second_counter) = raw_seal(&follower_dir, chain_head(&reopened).await);
    assert_ne!(second_prefix, file);
    assert_ne!(second_prefix, first_prefix);
    assert!(
        second_counter > first_counter,
        "the follower's counter must keep rising across its own runs"
    );
    let report = run_deep_walk(&reopened).await.unwrap();
    assert!(report.is_clean(), "{report:?}");
}
