//! Concurrency soak: the interleavings the sequential suite cannot express.
//!
//! Every scenario here runs its parties as genuinely concurrent Tokio tasks on
//! a multi-thread runtime — nothing is scripted into a fixed order. What the
//! scenarios have in common is the shape of their assertions:
//!
//! * **Structural integrity.** After the race quiesces, `run_deep_walk` on the
//!   handle that owns the allocator must report `is_clean()` — which counts
//!   leaked (unreferenced and unfree-listed) pages, not only bad bytes.
//! * **Commit atomicity.** The writer moves a fixed key set to a new
//!   *generation* in a single commit, and every value encodes both its key and
//!   its generation. A reader that observes two different generations across
//!   one `ReadTxn`, a missing key, or bytes that disagree with the generation
//!   they claim has observed a partial commit or a torn value.
//! * **Error discipline.** Every operation's result is classified. Errors the
//!   protocol genuinely permits are matched by variant; anything else fails the
//!   test rather than being swallowed.
//!
//! These are soaks, so they are `#[ignore]`d and the default suite stays fast:
//!
//! ```text
//! cargo nextest run --run-ignored all --test concurrency_stress
//! PAGEDB_STRESS_SCALE=8 cargo nextest run --run-ignored all --test concurrency_stress
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use pagedb::vfs::Vfs;
use pagedb::vfs::memory::MemVfs;
use pagedb::vfs::tokio_backend::TokioVfs;
use pagedb::{
    Db, OpenOptions, PagedbError, ReadTxn, ReaderStallPolicy, RealmId, SegmentKind,
    SegmentPageKind, run_deep_walk,
};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x4Bu8; 32];
const REALM: RealmId = RealmId::new([0x3Au8; 16]);

/// Keys in the generation set — the set that moves atomically per commit.
const GENERATION_KEYS: u32 = 64;
/// Keys written and deleted per churn round to keep freeing pages.
const CHURN_KEYS: u32 = 24;
/// Fixed value width, so a short read is detectable on its own.
const VALUE_LEN: usize = 320;

/// Work multiplier for every soak in this file: rounds *and* concurrent task
/// counts scale with it. Follows the `PAGEDB_PROPTEST_CASES` precedent — the
/// default keeps an explicit `--run-ignored all` run to a few seconds, and a
/// scheduled soak raises it.
fn stress_scale() -> u32 {
    std::env::var("PAGEDB_STRESS_SCALE")
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|scale| *scale > 0)
        .unwrap_or(1)
}

fn scaled(base: u32) -> u32 {
    base.saturating_mul(stress_scale())
}

fn reader_task_count(base: usize) -> usize {
    base.saturating_mul(stress_scale() as usize)
}

fn key(index: u32) -> Vec<u8> {
    format!("gen:{index:06}").into_bytes()
}

fn churn_key(round: u32, index: u32) -> Vec<u8> {
    format!("churn:{round:06}:{index:04}").into_bytes()
}

/// Value bytes for `key(index)` at `generation`. The generation and the key
/// index are both encoded in the payload and the body is derived from the two,
/// so a value assembled from two different commits cannot pass verification.
fn value(index: u32, generation: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; VALUE_LEN];
    bytes[0..4].copy_from_slice(&generation.to_le_bytes());
    bytes[4..8].copy_from_slice(&index.to_le_bytes());
    for (offset, byte) in bytes.iter_mut().enumerate().skip(8) {
        *byte = index
            .wrapping_mul(31)
            .wrapping_add(generation.wrapping_mul(7))
            .wrapping_add(offset as u32) as u8;
    }
    bytes
}

/// Recover the generation a stored value claims, verifying the whole payload
/// against the canonical encoding for that generation.
fn generation_of(index: u32, bytes: &[u8]) -> u32 {
    assert_eq!(
        bytes.len(),
        VALUE_LEN,
        "key {index} read back {} bytes, expected {VALUE_LEN} — torn value",
        bytes.len()
    );
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[0..4]);
    let generation = u32::from_le_bytes(raw);
    assert_eq!(
        bytes,
        value(index, generation).as_slice(),
        "key {index} claims generation {generation} but its bytes do not match that \
         generation — the value was assembled from more than one commit"
    );
    generation
}

/// Read the whole generation set through one pinned snapshot and return the
/// generation every key agrees on.
///
/// Panics on a torn snapshot (mixed generations, a missing key, or a value that
/// disagrees with its own generation tag). Transport errors are returned so the
/// caller can classify them against the set its scenario permits.
async fn snapshot_generation<V: Vfs + Clone>(
    txn: &ReadTxn<'_, V>,
    label: &str,
) -> Result<u32, PagedbError> {
    let mut observed: Option<u32> = None;
    for index in 0..GENERATION_KEYS {
        let bytes = txn.get(&key(index)).await?.unwrap_or_else(|| {
            panic!(
                "{label}: key {index} is absent from a committed snapshot — the commit that \
                 wrote the generation set was observed partially"
            )
        });
        let generation = generation_of(index, &bytes);
        match observed {
            None => observed = Some(generation),
            Some(first) => assert_eq!(
                first, generation,
                "{label}: key {index} is at generation {generation} while earlier keys are at \
                 {first} — one commit's key set was observed split across two generations"
            ),
        }
    }
    Ok(observed.expect("the generation set is never empty"))
}

/// Move the whole generation set to `generation` in a single commit.
async fn commit_generation<V: Vfs + Clone>(db: &Db<V>, generation: u32) -> Result<(), PagedbError> {
    let mut txn = db.begin_write().await?;
    for index in 0..GENERATION_KEYS {
        txn.put(&key(index), &value(index, generation)).await?;
    }
    txn.commit().await.map(|_commit_id| ())
}

/// Write then delete a scratch batch, so freed pages keep arriving at the
/// free-list / deferred-free machinery the other parties contend with.
async fn churn_scratch_pages<V: Vfs + Clone>(db: &Db<V>, round: u32) -> Result<(), PagedbError> {
    let mut txn = db.begin_write().await?;
    for index in 0..CHURN_KEYS {
        txn.put(&churn_key(round, index), &[0xA5u8; 512]).await?;
    }
    txn.commit().await?;

    let mut txn = db.begin_write().await?;
    for index in 0..CHURN_KEYS {
        txn.delete(&churn_key(round, index)).await?;
    }
    txn.commit().await?;
    Ok(())
}

async fn seed_generation_zero<V: Vfs + Clone>(db: &Db<V>) {
    commit_generation(db, 0)
        .await
        .expect("seeding the generation set must succeed on a quiet store");
}

/// Post-race verification shared by every scenario: one quiesced snapshot must
/// be internally consistent, and the deep walk must be clean on the handle that
/// owns the allocator behind `main.db`.
async fn assert_quiesced_and_clean<V: Vfs + Clone>(db: &Db<V>, label: &str) -> u32 {
    let generation = {
        let txn = db
            .begin_read()
            .await
            .unwrap_or_else(|error| panic!("{label}: begin_read failed: {error:?}"));
        let generation = snapshot_generation(&txn, label)
            .await
            .unwrap_or_else(|error| panic!("{label}: quiesced read failed: {error:?}"));
        drop(txn);
        generation
    };

    let report = run_deep_walk(db)
        .await
        .unwrap_or_else(|error| panic!("{label}: deep walk failed to run: {error:?}"));
    assert!(
        report.is_clean(),
        "{label}: deep walk is not clean — {} page issue(s) {:?}, {} segment issue(s) {:?}, \
         {} drift issue(s) {:?}, {} leaked page(s) {:?}",
        report.page_issues.len(),
        report.page_issues,
        report.segment_issues.len(),
        report.segment_issues,
        report.drift_issues.len(),
        report.drift_issues,
        report.orphan_page_ids.len(),
        report.orphan_page_ids,
    );
    generation
}

// ─────────────────────────────────────────────────────────────────────────────
// Readers pinned across a compaction
// ─────────────────────────────────────────────────────────────────────────────

/// Reader pins held *across* a running compaction must survive it unchanged,
/// and a compaction that gets a genuinely reader-free moment must still be able
/// to reclaim.
///
/// Compaction relocates pages and truncates the file, so it refuses while any
/// reader is pinned. The interleaving under test is the boundary between those
/// two states while a writer keeps committing: reader tasks open pins, verify
/// their snapshot, stay pinned while the compactor runs, and verify again;
/// meanwhile the compactor alternates between contended attempts and attempts
/// taken during a reader-free window. No party is permitted to fail: compaction
/// is a no-op under pins, not an error, and a pinned snapshot is immutable.
///
/// Soak: `#[ignore]`d so the default suite stays fast. Run with
/// `cargo nextest run --run-ignored all --test concurrency_stress`; scale with
/// `PAGEDB_STRESS_SCALE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running concurrency soak; run with --run-ignored all"]
async fn reader_pins_survive_a_concurrent_compaction() {
    let rounds = scaled(12);
    let db = Arc::new(
        Db::open(MemVfs::new(), KEK, PAGE, REALM, OpenOptions::default())
            .await
            .unwrap(),
    );
    seed_generation_zero(&db).await;

    let stop = Arc::new(AtomicBool::new(false));
    // Held for read while a task keeps a pin open; the compactor takes it for
    // write to obtain a window in which no reader is pinned at all.
    let pin_gate = Arc::new(tokio::sync::RwLock::new(()));

    let mut readers = Vec::new();
    for _ in 0..reader_task_count(3) {
        let db = db.clone();
        let stop = stop.clone();
        let pin_gate = pin_gate.clone();
        readers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let admitted = pin_gate.read().await;
                let txn = db.begin_read().await.expect("reader admission failed");
                let before = snapshot_generation(&txn, "pinned reader (before compaction)")
                    .await
                    .expect("a pinned reader must not fail while compaction runs");
                // Stay pinned long enough for the compactor to observe the pin.
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                }
                let after = snapshot_generation(&txn, "pinned reader (after compaction)")
                    .await
                    .expect("a pinned reader must not fail after compaction ran");
                assert_eq!(
                    before, after,
                    "a pinned snapshot moved while compaction ran concurrently"
                );
                drop(txn);
                drop(admitted);
                tokio::task::yield_now().await;
            }
        }));
    }

    let writer = {
        let db = db.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut generation = 1u32;
            while !stop.load(Ordering::Relaxed) {
                commit_generation(&db, generation)
                    .await
                    .expect("a commit must not fail while compaction runs");
                churn_scratch_pages(&db, generation)
                    .await
                    .expect("churn commits must not fail while compaction runs");
                generation += 1;
                tokio::task::yield_now().await;
            }
            generation - 1
        })
    };

    let mut reclaimed_pages = 0u64;
    for _ in 0..rounds {
        // Contended attempt: readers are (almost certainly) pinned, so this is
        // required to be a clean no-op rather than an error.
        db.compact_now()
            .await
            .expect("compaction under reader pins must be a no-op, not a failure");

        // Reader-free window: every reader task drops its pin before releasing
        // the gate, so this attempt can actually relocate and truncate.
        let exclusive = pin_gate.write().await;
        let stats = db
            .compact_now()
            .await
            .expect("compaction in a reader-free window must succeed");
        reclaimed_pages += stats.main_db_pages_reclaimed;
        drop(exclusive);
        tokio::task::yield_now().await;
    }

    stop.store(true, Ordering::Relaxed);
    let generations = writer.await.unwrap();
    for reader in readers {
        reader.await.unwrap();
    }

    assert!(
        reclaimed_pages > 0,
        "no compaction ever reclaimed a page — the soak never reached the state it exists to \
         exercise"
    );
    let final_generation = assert_quiesced_and_clean(&db, "compaction soak").await;
    assert_eq!(
        final_generation, generations,
        "the final visible generation is not the last one the writer committed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Rekey racing reader admission
// ─────────────────────────────────────────────────────────────────────────────

/// Readers admitted while a rekey is in flight must still resolve their
/// snapshot, and the rekeyed store must reopen under the new epoch.
///
/// Rekey rewrites every reachable page under a new master-key epoch while
/// holding the writer lock, but it does *not* close reader admission — so
/// readers are continuously being admitted, resolving roots, and reading pages
/// that the rekey may already have rewritten. The source epoch may only retire
/// once no reader can still resolve a pre-cutover snapshot; if that accounting
/// is wrong the symptom is a decryption/authentication failure on a live
/// reader, which this fails on. No error is permitted from any party.
///
/// Soak: `#[ignore]`d so the default suite stays fast. Run with
/// `cargo nextest run --run-ignored all --test concurrency_stress`; scale with
/// `PAGEDB_STRESS_SCALE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running concurrency soak; run with --run-ignored all"]
async fn readers_admitted_during_a_rekey_still_resolve_their_snapshot() {
    let epochs = scaled(6);
    let vfs = MemVfs::new();
    let db = Arc::new(
        Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
            .await
            .unwrap(),
    );
    seed_generation_zero(&db).await;

    let stop = Arc::new(AtomicBool::new(false));
    let admissions = Arc::new(AtomicU64::new(0));

    let mut readers = Vec::new();
    for _ in 0..reader_task_count(3) {
        let db = db.clone();
        let stop = stop.clone();
        let admissions = admissions.clone();
        readers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let txn = db
                    .begin_read()
                    .await
                    .expect("reader admission must not fail during a rekey");
                admissions.fetch_add(1, Ordering::Relaxed);
                let before = snapshot_generation(&txn, "reader admitted during rekey")
                    .await
                    .expect("a reader admitted during a rekey must resolve its snapshot");
                // Hold the pin across the epoch cutover.
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                let after = snapshot_generation(&txn, "reader held across rekey cutover")
                    .await
                    .expect("a reader must still resolve its pinned snapshot after a cutover");
                assert_eq!(
                    before, after,
                    "a pinned snapshot moved across a rekey epoch cutover"
                );
                drop(txn);
                tokio::task::yield_now().await;
            }
        }));
    }

    let writer = {
        let db = db.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut generation = 1u32;
            while !stop.load(Ordering::Relaxed) {
                commit_generation(&db, generation)
                    .await
                    .expect("a commit must not fail while a rekey runs");
                churn_scratch_pages(&db, generation)
                    .await
                    .expect("churn commits must not fail while a rekey runs");
                generation += 1;
                tokio::task::yield_now().await;
            }
            generation - 1
        })
    };

    for epoch in 1..=u64::from(epochs) {
        db.rekey_db(KEK, epoch)
            .await
            .unwrap_or_else(|error| panic!("rekey to epoch {epoch} failed: {error:?}"));
        tokio::task::yield_now().await;
    }

    stop.store(true, Ordering::Relaxed);
    let generations = writer.await.unwrap();
    for reader in readers {
        reader.await.unwrap();
    }
    assert!(
        admissions.load(Ordering::Relaxed) > 0,
        "no reader was ever admitted — the soak never raced anything"
    );

    let stats = db.stats().await.unwrap();
    assert_eq!(
        stats.mk_epoch,
        u64::from(epochs),
        "the store did not end on the last epoch the rekeys installed"
    );
    let live_generation = assert_quiesced_and_clean(&db, "rekey soak").await;
    assert_eq!(
        live_generation, generations,
        "the final visible generation is not the last one the writer committed"
    );

    // The rekeyed image must also be readable cold, under the epoch recorded in
    // its header — the durable half of the same property.
    let db = Arc::try_unwrap(db)
        .unwrap_or_else(|_| panic!("every task has joined; the handle must be uniquely owned"));
    drop(db);
    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .expect("a store rekeyed under concurrent readers must reopen");
    let reopened_generation = assert_quiesced_and_clean(&reopened, "rekey soak (reopened)").await;
    assert_eq!(
        reopened_generation, generations,
        "the reopened store does not carry the last committed generation"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// apply_incremental racing gc_now on a follower
// ─────────────────────────────────────────────────────────────────────────────

fn temp_root(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("pagedb-stress-{tag}-"))
        .tempdir()
        .unwrap()
}

async fn link_fresh_segment(db: &Db<TokioVfs>, name: &str, payload: &[u8]) {
    let mut writer = db
        .create_segment(REALM, SegmentKind::Unspecified)
        .await
        .unwrap();
    writer
        .append_page(SegmentPageKind::Data, payload)
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.link_segment(name, &meta).await.unwrap();
    txn.commit().await.unwrap();
}

/// A follower applying deltas while its own GC runs must converge on exactly
/// the producer's state, losing neither committed rows nor live segment files.
///
/// `apply_incremental` stages a whole target image and swaps it in, taking the
/// writer lock only for the tail of that protocol; `gc_now` takes the writer
/// lock and the visibility gate, then drains deferred tombstones and deletes
/// tombstoned files. So a GC can land in the middle of an apply's staging, and
/// the two disagree about which segment files are still needed unless the
/// tombstone accounting is exact. A GC that deletes a file the freshly applied
/// catalog still references shows up as catalog/disk drift in the deep walk; a
/// mis-sequenced apply shows up as a missing or stale row. Both parties are
/// required to succeed — neither has a permitted failure here.
///
/// Soak: `#[ignore]`d so the default suite stays fast. Run with
/// `cargo nextest run --run-ignored all --test concurrency_stress`; scale with
/// `PAGEDB_STRESS_SCALE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running concurrency soak; run with --run-ignored all"]
async fn follower_apply_incremental_races_gc_without_losing_state() {
    let source_root = temp_root("source");
    let snapshot_root = temp_root("snapshot");
    let follower_root = temp_root("follower");
    let delta_root = temp_root("delta");

    let source = Arc::new(
        Db::open(
            TokioVfs::new(source_root.path()),
            KEK,
            PAGE,
            REALM,
            OpenOptions::default(),
        )
        .await
        .unwrap(),
    );
    seed_generation_zero(&source).await;
    link_fresh_segment(&source, "seg-base", b"base-segment-page").await;

    // The follower starts from a full snapshot of that seeded state.
    source.snapshot_to(snapshot_root.path()).await.unwrap();
    let follower = Arc::new(
        Db::<TokioVfs>::restore_from(
            snapshot_root.path(),
            follower_root.path(),
            OpenOptions::default(),
            KEK,
        )
        .await
        .unwrap()
        .promote_to_follower()
        .await
        .unwrap(),
    );

    let stop = Arc::new(AtomicBool::new(false));

    // Producer: keeps committing generations and cycling segments, so every
    // delta carries both page changes and segment link/unlink side effects.
    let producer = {
        let source = source.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut generation = 1u32;
            while !stop.load(Ordering::Relaxed) {
                commit_generation(&source, generation)
                    .await
                    .expect("a producer commit must not fail while replication runs");
                link_fresh_segment(
                    &source,
                    &format!("seg-{generation:04}"),
                    format!("segment payload {generation}").as_bytes(),
                )
                .await;
                // The first segment this loop links is `seg-0001`, so trailing
                // the link by two only names a linked segment from the third
                // generation on. Starting at the second would ask the catalog
                // to unlink `seg-0000`, which never existed.
                if generation >= 3 {
                    let mut txn = source.begin_write().await.unwrap();
                    txn.unlink_segment(&format!("seg-{:04}", generation - 2))
                        .await
                        .unwrap();
                    txn.commit()
                        .await
                        .expect("unlinking a segment must not fail while replication runs");
                }
                generation += 1;
                tokio::task::yield_now().await;
            }
            generation - 1
        })
    };

    // The follower's own GC, running independently of the apply loop.
    let collector = {
        let follower = follower.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut runs = 0u64;
            while !stop.load(Ordering::Relaxed) {
                follower
                    .gc_now()
                    .await
                    .expect("gc_now must not fail while an incremental apply is in flight");
                runs += 1;
                tokio::task::yield_now().await;
            }
            runs
        })
    };

    // Replication loop: export the producer's delta from the follower's own
    // commit and apply it, racing the collector above on every iteration.
    //
    // Driven to a completion condition rather than a fixed attempt count. A
    // fixed count is a scheduling assumption: attempts that find the producer
    // has not advanced yet cost microseconds, so a fixed budget can be spent
    // before the producer's first commit lands and the soak measures nothing.
    // The bound below is a liveness backstop, and it reports how far the loop
    // actually got, so a producer that is genuinely starved by the concurrent
    // GC fails loudly instead of silently under-running.
    let target_applies = u64::from(scaled(6));
    let mut applies = 0u64;
    let mut attempts = 0u64;
    let mut round = 0u32;
    while applies < target_applies {
        attempts += 1;
        assert!(
            attempts < 200_000,
            "the replication loop stalled: {applies} of {target_applies} applies after \
             {attempts} attempts — the producer is not making progress against the concurrent \
             gc_now"
        );
        let base = follower.latest_commit();
        if source.latest_commit().value() <= base.value() {
            // A finished task here means it panicked (nothing has asked them to
            // stop yet); joining it surfaces that panic instead of spinning.
            if producer.is_finished() || collector.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
            continue;
        }
        let delta = delta_root.path().join(format!("delta-{round:06}"));
        round += 1;
        source
            .snapshot_incremental_to(base, &delta)
            .await
            .unwrap_or_else(|error| panic!("delta export from {base:?} failed: {error:?}"));
        follower
            .apply_incremental(&delta)
            .await
            .unwrap_or_else(|error| panic!("apply of delta from {base:?} failed: {error:?}"));
        applies += 1;
        assert!(
            follower.latest_commit().value() > base.value(),
            "apply_incremental reported success without advancing the follower"
        );
    }

    stop.store(true, Ordering::Relaxed);
    // Joined before the anti-vacuity gates: a panic inside either task is the
    // more precise failure and must not be masked by a count assertion.
    let generations = producer.await.unwrap();
    let gc_runs = collector.await.unwrap();
    assert!(
        generations > 0,
        "the producer never completed a write cycle — nothing was replicated"
    );
    assert_eq!(
        applies, target_applies,
        "the apply loop did not reach its target ({gc_runs} GC runs, {attempts} attempts)"
    );
    assert!(
        applies > 0 && gc_runs > 0,
        "the apply loop ({applies} applies) and the GC loop ({gc_runs} runs) did not both run — \
         nothing raced"
    );

    // Drain the remaining deltas now that the producer has stopped, so the
    // follower must converge exactly on the producer's final state.
    let mut drain = 0u32;
    while follower.latest_commit().value() < source.latest_commit().value() {
        let base = follower.latest_commit();
        let delta = delta_root.path().join(format!("drain-{drain:06}"));
        source.snapshot_incremental_to(base, &delta).await.unwrap();
        follower.apply_incremental(&delta).await.unwrap();
        drain += 1;
        assert!(
            drain < 10_000,
            "the follower never converged on the producer"
        );
    }
    follower
        .gc_now()
        .await
        .expect("a final gc_now on a converged follower must succeed");

    assert_eq!(
        follower.latest_commit().value(),
        source.latest_commit().value(),
        "the follower did not converge on the producer's commit"
    );

    // Rows: identical generation on both sides, and it is the last one written.
    let source_generation = assert_quiesced_and_clean(&source, "replication soak (producer)").await;
    assert_eq!(
        source_generation, generations,
        "the producer's visible generation is not the last one it committed"
    );
    let follower_generation =
        assert_quiesced_and_clean(&follower, "replication soak (follower)").await;
    assert_eq!(
        follower_generation, source_generation,
        "the follower's rows are at a different generation than the producer's"
    );

    // Segments: the same live set on both sides. A GC that ran a step too eager
    // shows up here as a segment the follower can no longer open.
    let mut source_segments: Vec<[u8; 16]> = source
        .list_segments(REALM, "")
        .await
        .unwrap()
        .into_iter()
        .map(|meta| meta.segment_id)
        .collect();
    let mut follower_segments: Vec<[u8; 16]> = follower
        .list_segments(REALM, "")
        .await
        .unwrap()
        .into_iter()
        .map(|meta| meta.segment_id)
        .collect();
    source_segments.sort_unstable();
    follower_segments.sort_unstable();
    assert_eq!(
        follower_segments, source_segments,
        "the follower's live segment set diverged from the producer's"
    );
    let newest_segment = format!("seg-{generations:04}");
    for name in ["seg-base", newest_segment.as_str()] {
        follower
            .open_segment(REALM, name)
            .await
            .unwrap_or_else(|error| panic!("live segment {name} unreadable on follower: {error:?}"))
            .read_page(1)
            .await
            .unwrap_or_else(|error| panic!("live segment {name} page unreadable: {error:?}"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reader-stall policy under genuine contention
// ─────────────────────────────────────────────────────────────────────────────

/// Options with a stall threshold low enough that ordinary churn under a reader
/// pin reaches it within a few commits.
fn stall_prone_options() -> OpenOptions {
    OpenOptions::default()
        .with_buffer_pool_pages(256)
        .with_reader_stall_threshold_pages(8)
}

/// Under `AbortOldest` and real contention, the abort is the *only* thing a
/// reader may observe: never a wrong value, and never on a non-abortable
/// reader.
///
/// The policy is evaluated inside a commit, against a tracked-reader table that
/// concurrent tasks are mutating — readers register and unregister while the
/// writer picks a victim. The permitted error set is exactly `Aborted` for
/// abortable readers and `DeferredFreeBacklog` for a commit that finds only
/// non-abortable readers blocking; both are matched by variant. An abortable
/// reader that survives must still see an untorn snapshot, and the
/// non-abortable reader must never be aborted at all.
///
/// Soak: `#[ignore]`d so the default suite stays fast. Run with
/// `cargo nextest run --run-ignored all --test concurrency_stress`; scale with
/// `PAGEDB_STRESS_SCALE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running concurrency soak; run with --run-ignored all"]
async fn abort_oldest_under_contention_aborts_readers_without_corrupting_them() {
    let rounds = scaled(30);
    let vfs = MemVfs::new();
    let db = Arc::new(
        Db::open(vfs.clone(), KEK, PAGE, REALM, stall_prone_options())
            .await
            .unwrap(),
    );
    db.set_reader_stall_policy(ReaderStallPolicy::AbortOldest);
    seed_generation_zero(&db).await;

    let stop = Arc::new(AtomicBool::new(false));
    let aborts = Arc::new(AtomicU64::new(0));

    let mut readers = Vec::new();
    for _ in 0..reader_task_count(3) {
        let db = db.clone();
        let stop = stop.clone();
        let aborts = aborts.clone();
        readers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let txn = db.begin_read().await.expect("reader admission failed");
                for _ in 0..3 {
                    match snapshot_generation(&txn, "abortable reader").await {
                        // A surviving read is verified inside snapshot_generation.
                        Ok(_) => {}
                        // The one-shot abort is the permitted outcome; the txn
                        // stays usable afterwards, so keep reading with it.
                        Err(PagedbError::Aborted) => {
                            aborts.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(other) => {
                            panic!("AbortOldest permits only Aborted on a reader, got {other:?}")
                        }
                    }
                    tokio::task::yield_now().await;
                }
                drop(txn);
                tokio::task::yield_now().await;
            }
        }));
    }

    // One long-lived non-abortable reader: exempt from AbortOldest for its
    // whole life, and holding the reclamation floor down the entire run.
    let protected = {
        let db = db.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let txn = db
                .begin_read_non_abortable()
                .await
                .expect("non-abortable admission failed");
            let pinned = snapshot_generation(&txn, "non-abortable reader")
                .await
                .expect("a non-abortable reader must never be aborted");
            while !stop.load(Ordering::Relaxed) {
                let observed = snapshot_generation(&txn, "non-abortable reader")
                    .await
                    .expect("a non-abortable reader must never be aborted");
                assert_eq!(
                    observed, pinned,
                    "the non-abortable reader's pinned snapshot moved under it"
                );
                tokio::task::yield_now().await;
            }
        })
    };

    let mut rejected_commits = 0u64;
    let mut generation = 1u32;
    for _ in 0..rounds {
        match commit_generation(&db, generation).await {
            Ok(()) => generation += 1,
            // Only reachable when every reader blocking the drain at evaluation
            // time is non-abortable; the commit is refused, not partially done.
            Err(PagedbError::DeferredFreeBacklog { .. }) => rejected_commits += 1,
            Err(other) => {
                panic!("AbortOldest permits only DeferredFreeBacklog on a commit, got {other:?}")
            }
        }
        match churn_scratch_pages(&db, generation).await {
            Ok(()) => {}
            Err(PagedbError::DeferredFreeBacklog { .. }) => rejected_commits += 1,
            Err(other) => {
                panic!("AbortOldest permits only DeferredFreeBacklog on a commit, got {other:?}")
            }
        }
        tokio::task::yield_now().await;
    }

    stop.store(true, Ordering::Relaxed);
    protected.await.unwrap();
    for reader in readers {
        reader.await.unwrap();
    }

    assert!(
        aborts.load(Ordering::Relaxed) > 0,
        "no reader was ever aborted ({rejected_commits} commit(s) rejected) — the stall policy \
         never fired, so this soak proved nothing about it"
    );

    // The deep walk asserts a property of the *durable* store, so it runs on a
    // reopened handle. A refused commit is deliberately never published, but the
    // live handle keeps whatever allocation cursor that attempt advanced; a
    // reopen restores the cursor the durable header names, so the walk is asked
    // about state that was actually committed. Anything the walk still reports
    // after this is durable, not an artifact of an unpublished attempt.
    let db = Arc::try_unwrap(db)
        .unwrap_or_else(|_| panic!("every task has joined; the handle must be uniquely owned"));
    drop(db);
    let reopened = Db::open(vfs, KEK, PAGE, REALM, stall_prone_options())
        .await
        .expect("a store that aborted readers under contention must reopen");
    let durable_generation = assert_quiesced_and_clean(&reopened, "AbortOldest soak").await;
    assert_eq!(
        durable_generation,
        generation - 1,
        "the durable generation is not the last commit the writer completed"
    );
}

/// Under `Reject`, the pressure lands on the writer and never on a reader: a
/// commit may be refused, but no reader is ever aborted and no refused commit
/// leaves partial state behind.
///
/// This is the mirror of the `AbortOldest` soak against the same contention:
/// the permitted error set is exactly `DeferredFreeBacklog` on a commit, and
/// *empty* for readers. A refused commit must be a full no-op, which the
/// generation encoding checks — the visible generation must equal the last
/// commit that actually returned `Ok`.
///
/// Soak: `#[ignore]`d so the default suite stays fast. Run with
/// `cargo nextest run --run-ignored all --test concurrency_stress`; scale with
/// `PAGEDB_STRESS_SCALE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running concurrency soak; run with --run-ignored all"]
async fn reject_under_contention_refuses_commits_without_touching_readers() {
    let rounds = scaled(30);
    let vfs = MemVfs::new();
    let db = Arc::new(
        Db::open(vfs.clone(), KEK, PAGE, REALM, stall_prone_options())
            .await
            .unwrap(),
    );
    db.set_reader_stall_policy(ReaderStallPolicy::Reject);
    seed_generation_zero(&db).await;

    let stop = Arc::new(AtomicBool::new(false));

    let mut readers = Vec::new();
    for _ in 0..reader_task_count(3) {
        let db = db.clone();
        let stop = stop.clone();
        readers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let txn = db.begin_read().await.expect("reader admission failed");
                let before = snapshot_generation(&txn, "reader under Reject")
                    .await
                    .expect("Reject must never surface an error on a reader");
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                let after = snapshot_generation(&txn, "reader under Reject")
                    .await
                    .expect("Reject must never surface an error on a reader");
                assert_eq!(
                    before, after,
                    "a pinned snapshot moved while commits were being rejected"
                );
                drop(txn);
                tokio::task::yield_now().await;
            }
        }));
    }

    let mut rejected_commits = 0u64;
    let mut committed_generation = 0u32;
    let mut attempt = 1u32;
    for _ in 0..rounds {
        match commit_generation(&db, attempt).await {
            Ok(()) => {
                committed_generation = attempt;
                attempt += 1;
            }
            Err(PagedbError::DeferredFreeBacklog { .. }) => rejected_commits += 1,
            Err(other) => {
                panic!("Reject permits only DeferredFreeBacklog on a commit, got {other:?}")
            }
        }
        match churn_scratch_pages(&db, attempt).await {
            Ok(()) => {}
            Err(PagedbError::DeferredFreeBacklog { .. }) => rejected_commits += 1,
            Err(other) => {
                panic!("Reject permits only DeferredFreeBacklog on a commit, got {other:?}")
            }
        }
        tokio::task::yield_now().await;
    }

    stop.store(true, Ordering::Relaxed);
    for reader in readers {
        reader.await.unwrap();
    }

    assert!(
        rejected_commits > 0,
        "no commit was ever rejected — the stall policy never fired, so this soak proved nothing \
         about it"
    );

    // Walk the durable store, not the live handle: `Reject` refuses commits
    // after the attempt has already advanced the live allocation cursor, and
    // that cursor is never published. A reopen restores the cursor from the
    // durable header, so what the walk reports is what the store actually
    // committed — a leak that survives this reopen is a durable leak.
    let db = Arc::try_unwrap(db)
        .unwrap_or_else(|_| panic!("every task has joined; the handle must be uniquely owned"));
    drop(db);
    let reopened = Db::open(vfs, KEK, PAGE, REALM, stall_prone_options())
        .await
        .expect("a store whose commits were rejected under contention must reopen");
    let durable_generation = assert_quiesced_and_clean(&reopened, "Reject soak").await;
    assert_eq!(
        durable_generation, committed_generation,
        "the durable generation does not match the last commit that returned Ok — a rejected \
         commit left state behind"
    );
}
