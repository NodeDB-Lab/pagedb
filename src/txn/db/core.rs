//! `Db<V>` struct definition, its small companion types, and the shared
//! header-field / catalog-root encoding helpers used across the writer paths.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};

use crate::crypto::CipherId;
use crate::errors::PagedbError;
use crate::options::OpenOptions;
use crate::pager::Pager;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;
use crate::{CommitId, RealmId, Result};

use super::super::mode::DbMode;
use super::super::policy::ReaderStallPolicy;
use super::segment::SegmentReconciliation;
use crate::txn::write::SegmentSideEffect;

/// A segment tombstone that was deferred because a reader was pinning it at
/// commit time.
#[derive(Debug, Clone)]
pub(crate) struct PendingTombstone {
    pub segment_id: [u8; 16],
    pub commit_id: u64,
}

/// A source epoch that remains leased until all tracked pre-cutover readers
/// have released their snapshot pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingKeyRetirement {
    pub epoch: u64,
    pub cipher_id: CipherId,
}

/// One registered reader's pin record. Held in the `Db`'s tracked-reader `Vec`.
#[derive(Debug)]
pub(crate) struct TrackedReader {
    pub entry_id: u64,
    pub commit_id: CommitId,
    #[allow(dead_code)]
    pub root_page_id: u64,
    pub next_page_id: u64,
    pub catalog_root_page_id: u64,
    pub non_abortable: bool,
}

/// Writer state, guarded by the writer mutex. Holds the current root and
/// allocation cursor; on commit the new values get persisted to the header.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct VisibilityTestHook {
    pub(crate) reader_selected: tokio::sync::Notify,
    pub(crate) allow_reader_registration: tokio::sync::Notify,
    pub(crate) reader_registered: tokio::sync::Notify,
    pub(crate) reader_may_read: tokio::sync::Notify,
    pub(crate) writer_waiting: tokio::sync::Notify,
    /// Raised by an incremental apply once it is inside its publication
    /// window: the tombstone pin scan has run, the live file is the target
    /// image, and the target snapshot is not published yet.
    pub(crate) apply_window_entered: tokio::sync::Notify,
    /// Lets the apply leave that window. A test admits (or fails to admit) a
    /// reader in between.
    pub(crate) apply_window_release: tokio::sync::Notify,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RekeyTestFault {
    Intent,
    MainPagesTargetReadable,
    HeaderTargetPublished,
    /// The main database is fully target-sealed and the intent says so, but no
    /// segment has been touched yet. Without a fault here a crash landing in
    /// `MainDone` cannot be produced at all, so the resume path that starts
    /// from it is never entered.
    MainDone,
    /// The intent has been advanced to segments-pending and made durable, and
    /// the segment migration has not begun.
    SegmentsPending,
    SegmentSeal,
    ProgressRowCommit,
    CatalogSwapEffects,
    ProgressDeletion,
}

/// The A/B slot and sequence a header write must use are deliberately absent
/// here: they live in the Pager's header cursor, which an anchor refresh can
/// advance between two commits without the writer being involved. Two copies
/// would let a refresh and a commit disagree about which slot is live, and the
/// loser of that disagreement is a committed transaction.
pub(crate) struct WriterState {
    pub root_page_id: u64,
    pub next_page_id: u64,
    pub latest_commit_id: u64,
    pub catalog_root_page_id: u64,
    pub catalog_root_txn_id: u64,
    /// Head page id of the durable free-list chain (0 = empty). Stored in the
    /// A/B header's `free_list_root` slot and rewritten atomically with each
    /// commit. See [`crate::pager::freelist`].
    pub free_list_root_page_id: u64,
    /// Root page id of the commit-history B+ tree (0 = not yet created).
    pub commit_history_root_page_id: u64,
    /// Version / `txn_id` of the commit-history tree's last write.
    pub commit_history_root_version: u64,
    /// Cached number of entries in the commit-history tree. Maintained by
    /// `write_commit_history_entry` so pruning can skip the full
    /// `collect_range` scan when the count is provably below the retain
    /// limit. `None` means "not yet populated; refresh from disk on first
    /// use". Re-populated lazily after a reopen.
    pub commit_history_count: Option<u64>,
    /// Identity of the apply journal named by the durable header. A zero id
    /// means no apply sidecar is pending reconciliation.
    pub pending_apply_journal_id: [u8; 16],
    /// Header mode preserved by every recovery header rewrite.
    pub restore_mode: u8,
    /// Header commit-history retention fields preserved by recovery rewrites.
    pub commit_retain_policy_tag: u8,
    pub commit_retain_policy_value: u64,
}

/// Top-level handle to an open database.
///
/// `V` must implement `Clone`; the `Db` keeps one `Arc<V>` for header
/// operations while the `Pager` owns a separate cloned instance for data I/O.
/// `MemVfs` satisfies this via its own `#[derive(Clone)]` (shared `Arc`
/// internals). Native VFS backends introduced in later slices will satisfy it
/// the same way.
pub struct Db<V: Vfs + Clone> {
    pub(crate) pager: Arc<Pager<V>>,
    pub(crate) realm_id: RealmId,
    pub(crate) page_size: usize,
    /// Header Key (HK) used to sign A/B header commits. Held in an `RwLock`
    /// so it can be updated atomically during an online rekey without
    /// rebuilding the `Db` handle, and behind an `Arc` because the Pager holds
    /// the same handle to sign the anchor refreshes it writes on its own.
    pub(crate) hk: Arc<parking_lot::RwLock<crate::crypto::keys::DerivedKey>>,
    pub(crate) main_db_path: String,
    pub(crate) vfs: Arc<V>,
    pub(crate) writer: Arc<AsyncMutex<WriterState>>,
    /// Serializes the complete incremental-apply protocol, including manifest
    /// validation, journal recovery, image staging, and segment staging.
    /// Its sole consumer, `snapshot::apply_incremental`, is native-only
    /// (`#![cfg(not(target_arch = "wasm32"))]`), so the field itself is gated
    /// the same way.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) apply_gate: AsyncMutex<()>,
    /// Serializes reader admission against destructive visibility changes.
    ///
    /// Lock ordering is fixed: writer and apply locks are acquired before this
    /// write lock; reader admission acquires only this read lock. Tokio guards
    /// may cross awaits, while no guard from `parking_lot` may do so.
    pub(crate) visibility_gate: AsyncRwLock<()>,
    pub(crate) tracked_readers: parking_lot::Mutex<Vec<TrackedReader>>,
    pub(crate) reader_seq: AtomicU64,
    pub(crate) stall_policy: parking_lot::Mutex<ReaderStallPolicy>,
    pub(crate) cipher_id: CipherId,
    /// Authenticated structural fields copied from the selected A/B header so
    /// non-ordinary writers (including rekey) can preserve them verbatim.
    pub(crate) format_version: u16,
    pub(crate) header_flags: u32,
    pub(crate) mk_epoch: AtomicU64,
    pub(crate) file_id: [u8; 16],
    pub(crate) kek_salt: [u8; 16],
    pub(crate) pending_tombstones: parking_lot::Mutex<Vec<PendingTombstone>>,
    pub(crate) pending_key_retirements: parking_lot::Mutex<Vec<PendingKeyRetirement>>,
    pub(crate) options: OpenOptions,
    /// Running total of bytes currently charged to `mmap_view_scratch_bytes`.
    /// Shared with live `MmapView` handles via `Arc` so they can decrement on drop.
    pub(crate) mmap_bytes_in_use: std::sync::Arc<AtomicU64>,
    /// Cumulative spill bytes written to the current active write transaction's
    /// tmp file. Reset to 0 when the write transaction commits or aborts.
    pub(crate) spill_bytes_in_use: AtomicU64,
    /// Monotonically increasing counter assigned to each `WriteTxn` at begin.
    /// Each txn gets `txn_seq.fetch_add(1, Relaxed)` (first txn gets 1 since
    /// we start at 0 and add-then-use the pre-increment value + 1).
    pub(crate) txn_seq: AtomicU64,
    /// Random per-open identity mixed into every spill key derivation. The
    /// counter above restarts at 1 on each open and also supplies the spill
    /// nonce, so this is what stops two opens of one store from encrypting
    /// different scratch under the same key at the same nonce.
    pub(crate) spill_epoch: [u8; 16],
    /// Scratch paths belonging to write transactions that were dropped without
    /// `commit` or `abort`. `Drop` cannot await the VFS removal, so it records
    /// the exact path here and the next `begin_write` — which holds the writer
    /// lock and can await — removes it. Anything still listed when the handle
    /// closes is swept by the next open.
    pub(crate) orphaned_spill_paths: parking_lot::Mutex<Vec<String>>,
    /// The mode this handle was opened with (Standalone, Follower, `ReadOnly`, Observer).
    pub(crate) mode: DbMode,
    /// Set of reader `entry_id`s that have been aborted by `AbortOldest` stall
    /// policy. Checked at the start of every `ReadTxn` operation; the entry is
    /// removed once the reader observes the abort.
    pub(crate) aborted_readers: parking_lot::Mutex<std::collections::HashSet<u64>>,
    /// Whether [`Self::aborted_readers`] currently holds anything.
    ///
    /// Aborting a reader is rare; checking whether one was aborted happens at
    /// the head of every read operation. Without this the common answer — "no"
    /// — costs a mutex acquisition and a hash lookup. A reader that races an
    /// abort landing just after its load observes it on its next operation,
    /// which is already the guarantee: the abort is delivered to the reader's
    /// *next* call, not to one in flight.
    pub(crate) any_reader_aborted: std::sync::atomic::AtomicBool,
    /// Sentinel-lock handles acquired at open. Released (dropped) when the `Db` drops.
    pub(crate) sentinel_locks: Vec<<V as Vfs>::LockHandle>,
    /// Set only by open paths that actually run the sentinel-lock acquisition
    /// sequence for a writer mode (`open_with_mode`'s Standalone/Follower
    /// dispatch, the locking `open_internal_with_options_and_cipher` wrapper,
    /// and `promote_to_follower`). Constructors that bypass locking on
    /// purpose — `open_existing`'s direct entry points, meant to be reached
    /// through `Db::open` — leave this `false`, so the debug-only write guard
    /// only fires where a lock was actually supposed to be held.
    pub(crate) lock_required: bool,
    /// Snapshot of the reader-visible roots, published atomically at each
    /// writer commit. Read-only paths use this as their sole current-state
    /// publication channel, so readers see either the prior complete commit or
    /// the next complete commit.
    pub(crate) snapshot: Arc<parking_lot::RwLock<ReaderSnapshot>>,
    /// The durable commit that could not be reconciled into `snapshot`.
    /// Existing readers retain their pinned snapshots; all new state-dependent
    /// operations fail until the database is reopened.
    pub(crate) poisoned_commit: parking_lot::Mutex<Option<CommitId>>,
    /// Cross-commit cache of page IDs known to be safely reusable. Populated
    /// after each commit with the pages it freed that no live reader and no
    /// retained commit-history root can still observe; the next writer txn's
    /// `allocate_page` pops from here before bumping `next_page_id`, keeping the
    /// file size bounded under sustained writes. Shared with each session's
    /// `BTree` via the same `Arc` so all three trees in a txn (main, catalog,
    /// history) draw from the same pool. Cleared by `compact_now`'s full repack,
    /// which relocates pages and invalidates every cached id.
    pub(crate) free_page_cache: Arc<parking_lot::Mutex<Vec<u64>>>,
    /// Per-txn sink (cleared at `begin_write`) recording page ids the allocator
    /// drew from `free_page_cache`. The commit path removes them from the
    /// durable free-list — they now hold live committed data.
    pub(crate) free_page_consumed: Arc<parking_lot::Mutex<Vec<u64>>>,
    #[cfg(test)]
    pub(crate) visibility_test_hook: parking_lot::Mutex<Option<Arc<VisibilityTestHook>>>,
    #[cfg(test)]
    pub(crate) rekey_test_fault: parking_lot::Mutex<Option<RekeyTestFault>>,
}

/// Reader-visible state, refreshed by the writer at commit time.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub(crate) struct ReaderSnapshot {
    pub commit_id: u64,
    pub root_page_id: u64,
    pub next_page_id: u64,
    pub catalog_root_page_id: u64,
    pub free_list_root_page_id: u64,
    /// Commit-history root accompanying this published snapshot. Historical
    /// reader admission resolves from this immutable root without taking the
    /// writer lock.
    pub commit_history_root_page_id: u64,
}

/// Encode a 16-byte catalog/free-list root reference: `page_id` (LE u64) in the
/// low 8 bytes followed by `txn_id` (LE u64) in the high 8 bytes.
pub(super) fn encode_root_ref(page_id: u64, txn_id: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&page_id.to_le_bytes());
    bytes[8..].copy_from_slice(&txn_id.to_le_bytes());
    bytes
}

/// Encode the header's `free_list_root` slot from the free-list chain head page
/// id (low 8 bytes, LE; remaining bytes reserved/zero).
#[must_use]
pub(crate) fn encode_free_list_root(head_page_id: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&head_page_id.to_le_bytes());
    bytes
}

/// Decode the free-list chain head page id from the header's `free_list_root`.
#[must_use]
pub(crate) fn decode_free_list_root(raw: &[u8; 16]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw[..8]);
    u64::from_le_bytes(b)
}

/// Variable fields supplied per call site when assembling a
/// [`MainDbHeaderFields`] for a writer header commit. The constant fields
/// (`format_version`, `flags`, identity bytes, and the no-pending-journal
/// default) are filled in by [`Db::header_fields`].
#[derive(Clone, Copy)]
pub(super) struct HeaderFieldsParams {
    pub mk_epoch: u64,
    pub seq: u64,
    pub active_root_page_id: u64,
    pub active_root_txn_id: u64,
    pub counter_anchor: u64,
    pub commit_id: u64,
    pub catalog_root: [u8; 16],
    pub commit_history_root_page_id: u64,
    pub commit_history_root_version: u64,
    pub next_page_id: u64,
    /// Head page id of the durable free-list chain to record in the header.
    /// Header writes that don't touch the free list pass the current
    /// `state.free_list_root_page_id` so it is preserved across the swap.
    pub free_list_root_page_id: u64,
}

impl<V: Vfs + Clone> Db<V> {
    /// Whether this handle currently holds a writer sentinel lock
    /// (`.writer.lock`, acquired for `Standalone`/`Follower` mode).
    fn holds_write_lock(&self) -> bool {
        !self.sentinel_locks.is_empty()
    }

    /// Debug-only write-path guard: true unless this handle was opened
    /// through a path that was supposed to hold the writer sentinel
    /// (`lock_required`) but doesn't. Handles opened through locking-exempt
    /// entry points (`lock_required == false`) always pass — see the
    /// `lock_required` field doc for which those are. Used by
    /// `debug_assert!`; release builds pay nothing for this check.
    pub(crate) fn write_lock_satisfied(&self) -> bool {
        !self.lock_required || self.holds_write_lock()
    }

    /// Retire an obsolete source epoch immediately when no reader can still
    /// resolve a pre-cutover snapshot; otherwise defer retirement until the
    /// tracked reader set drains.
    pub(crate) fn retire_rekey_source_when_safe(
        &self,
        epoch: u64,
        cipher_id: CipherId,
    ) -> Result<()> {
        if self.tracked_readers.lock().is_empty() {
            return self.pager.retire_mk_epoch(epoch, cipher_id);
        }
        let pending = PendingKeyRetirement { epoch, cipher_id };
        let mut retirements = self.pending_key_retirements.lock();
        if !retirements.contains(&pending) {
            retirements.push(pending);
        }
        Ok(())
    }

    /// Drain deferred source-epoch retirements once no tracked reader remains.
    pub(crate) fn drain_pending_key_retirements(&self) -> Result<()> {
        if !self.tracked_readers.lock().is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut *self.pending_key_retirements.lock());
        for retirement in pending {
            self.pager
                .retire_mk_epoch(retirement.epoch, retirement.cipher_id)?;
        }
        Ok(())
    }

    pub(crate) fn ensure_usable(&self) -> Result<()> {
        match *self.poisoned_commit.lock() {
            Some(commit) => Err(PagedbError::durably_committed_but_unpublished(commit)),
            None => Ok(()),
        }
    }

    pub(crate) fn poison(&self, commit: CommitId) {
        let mut poisoned = self.poisoned_commit.lock();
        if poisoned.is_none() {
            *poisoned = Some(commit);
        }
    }

    /// Finish a commit whose header is already durable and whose writer state
    /// already names that durable snapshot. The prior reader snapshot remains
    /// visible until the nonce anchor and all required segment effects succeed.
    /// A failed post-header operation leaves the handle poisoned: advancing it
    /// again could expose a catalog whose filesystem side effects are unknown.
    pub(crate) async fn finish_durable_commit(
        &self,
        state: &WriterState,
        commit: CommitId,
        counter_anchor: u64,
        effects: &[SegmentSideEffect],
    ) -> Result<SegmentReconciliation> {
        #[cfg(test)]
        self.notify_writer_waiting();
        let visibility = self.visibility_gate.write().await;
        self.finish_durable_commit_visible(&visibility, state, commit, counter_anchor, effects)
            .await
    }

    /// Complete a durable commit while the caller holds `visibility_gate`'s
    /// write guard. `WriteTxn` uses this after taking the guard before its
    /// reclamation-floor scan, preserving the gate through publication.
    pub(crate) async fn finish_durable_commit_visible(
        &self,
        _visibility: &tokio::sync::RwLockWriteGuard<'_, ()>,
        state: &WriterState,
        commit: CommitId,
        counter_anchor: u64,
        effects: &[SegmentSideEffect],
    ) -> Result<SegmentReconciliation> {
        if let Err(error) = self.pager.commit_anchor(counter_anchor) {
            tracing::error!(commit = commit.0, error = %error, "durable commit anchor failed");
            self.poison(commit);
            return Err(PagedbError::durably_committed_but_unpublished(commit));
        }
        match self.reconcile_segment_effects(effects, commit.0).await {
            Ok(outcome) => {
                self.publish_snapshot(state);
                Ok(outcome)
            }
            Err(error) => {
                tracing::error!(commit = commit.0, error = %error, "durable commit reconciliation failed");
                self.poison(commit);
                Err(PagedbError::durably_committed_but_unpublished(commit))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn install_visibility_test_hook(&self, hook: Arc<VisibilityTestHook>) {
        *self.visibility_test_hook.lock() = Some(hook);
    }

    /// Detach the hook so the rest of a test runs on unrehearsed paths. Every
    /// pause point is a rendezvous that only completes when its counterpart
    /// notifies, so a hook left installed past the interleaving it was staging
    /// would park the next ordinary `begin_read`.
    #[cfg(test)]
    pub(crate) fn clear_visibility_test_hook(&self) {
        *self.visibility_test_hook.lock() = None;
    }

    #[cfg(test)]
    pub(crate) fn interrupt_rekey_after(&self, point: RekeyTestFault) {
        *self.rekey_test_fault.lock() = Some(point);
    }

    #[cfg(test)]
    pub(crate) fn interrupt_rekey_if_requested(&self, point: RekeyTestFault) -> Result<()> {
        let mut fault = self.rekey_test_fault.lock();
        if *fault == Some(point) {
            *fault = None;
            return Err(PagedbError::Io(std::io::Error::other(
                "rekey test interruption",
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn pause_after_snapshot_selection(&self) {
        let hook = self.visibility_test_hook.lock().clone();
        if let Some(hook) = hook {
            hook.reader_selected.notify_one();
            hook.allow_reader_registration.notified().await;
        }
    }

    /// Hold an incremental apply inside its publication window so a test can
    /// try to admit a reader there. Mirrors
    /// [`Self::pause_after_snapshot_selection`]: inert unless a hook is
    /// installed.
    #[cfg(test)]
    pub(crate) async fn pause_in_apply_publication_window(&self) {
        let hook = self.visibility_test_hook.lock().clone();
        if let Some(hook) = hook {
            hook.apply_window_entered.notify_one();
            hook.apply_window_release.notified().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn notify_reader_registered(&self) {
        if let Some(hook) = self.visibility_test_hook.lock().clone() {
            hook.reader_registered.notify_one();
        }
    }

    #[cfg(test)]
    pub(crate) fn notify_writer_waiting(&self) {
        if let Some(hook) = self.visibility_test_hook.lock().clone() {
            hook.writer_waiting.notify_one();
        }
    }

    /// Parent directory whose metadata contains `main.db` and its compaction
    /// scratch replacement.
    #[must_use]
    pub(crate) fn main_db_parent_dir(&self) -> &str {
        match self.main_db_path.rsplit_once('/') {
            Some(("", _)) | None => "/",
            Some((parent, _)) => parent,
        }
    }

    /// Assemble a [`MainDbHeaderFields`] for a writer header commit, filling in
    /// the fields that are constant across every writer commit path (identity,
    /// format version, and the apply-journal / restore-mode / retain-policy
    /// fields that are always zero on these paths) from `self`, and taking the
    /// per-commit variable fields from `params`.
    pub(super) fn header_fields(&self, params: HeaderFieldsParams) -> Result<MainDbHeaderFields> {
        Ok(MainDbHeaderFields {
            format_version: self.format_version,
            cipher_id: self.cipher_id.as_byte(),
            page_size_log2: super::util::page_size_log2(self.page_size)?,
            flags: self.header_flags,
            file_id: self.file_id,
            kek_salt: self.kek_salt,
            mk_epoch: params.mk_epoch,
            seq: params.seq,
            active_root_page_id: params.active_root_page_id,
            active_root_txn_id: params.active_root_txn_id,
            counter_anchor: params.counter_anchor,
            commit_id: CommitId(params.commit_id),
            free_list_root: encode_free_list_root(params.free_list_root_page_id),
            catalog_root: params.catalog_root,
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: params.commit_history_root_page_id,
            commit_history_root_version: params.commit_history_root_version,
            restore_mode: 0,
            next_page_id: params.next_page_id,
            commit_retain_policy_tag: 0,
            commit_retain_policy_value: 0,
        })
    }
}

/// Packed representation of a historical commit's roots. 40 bytes on disk:
/// `active_root_page_id` (8) | `catalog_root_page_id` (8) | `free_list_root_page_id` (8)
/// | `next_page_id` (8) | `unix_seconds` (8).
pub(crate) struct CommitHistoryMeta {
    pub active_root_page_id: u64,
    pub catalog_root_page_id: u64,
    pub free_list_root_page_id: u64,
    pub next_page_id: u64,
    pub unix_seconds: u64,
}

pub(crate) fn encode_commit_meta(m: &CommitHistoryMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&m.active_root_page_id.to_le_bytes());
    out.extend_from_slice(&m.catalog_root_page_id.to_le_bytes());
    out.extend_from_slice(&m.free_list_root_page_id.to_le_bytes());
    out.extend_from_slice(&m.next_page_id.to_le_bytes());
    out.extend_from_slice(&m.unix_seconds.to_le_bytes());
    out
}

pub(crate) fn decode_commit_meta(bytes: &[u8]) -> Result<CommitHistoryMeta> {
    if bytes.len() < 40 {
        return Err(PagedbError::catalog_row_invalid("commit_history.meta"));
    }
    let read_u64 = |b: &[u8], off: usize| {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[off..off + 8]);
        u64::from_le_bytes(a)
    };
    Ok(CommitHistoryMeta {
        active_root_page_id: read_u64(bytes, 0),
        catalog_root_page_id: read_u64(bytes, 8),
        free_list_root_page_id: read_u64(bytes, 16),
        next_page_id: read_u64(bytes, 24),
        unix_seconds: read_u64(bytes, 32),
    })
}

/// Generated adversarial input for the commit-history row decoder.
///
/// The row is reached through a `pub(crate)` path, so it has no integration
/// surface to test from — widening its visibility to make it reachable would
/// enlarge the published API to serve a test, which is the wrong trade. The
/// property lives beside the code instead.
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{CommitHistoryMeta, decode_commit_meta, encode_commit_meta};

    const META_LEN: usize = 40;

    fn cases() -> u32 {
        std::env::var("PAGEDB_PROPTEST_CASES")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(32)
    }

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: cases(),
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// A short row must be declined, never sliced. Trailing bytes are
        /// tolerated by design (the row is a fixed prefix), so acceptance is
        /// exactly "at least the fixed width".
        #[test]
        fn random_bytes_are_accepted_only_at_or_above_the_fixed_width(
            bytes in prop::collection::vec(any::<u8>(), 0..=(META_LEN + 16)),
        ) {
            match decode_commit_meta(&bytes) {
                Ok(_) => prop_assert!(bytes.len() >= META_LEN),
                Err(_) => prop_assert!(bytes.len() < META_LEN),
            }
        }

        #[test]
        fn encoded_rows_round_trip_for_every_field_value(
            active_root_page_id in any::<u64>(),
            catalog_root_page_id in any::<u64>(),
            free_list_root_page_id in any::<u64>(),
            next_page_id in any::<u64>(),
            unix_seconds in any::<u64>(),
            trailing in prop::collection::vec(any::<u8>(), 0..=16),
        ) {
            let meta = CommitHistoryMeta {
                active_root_page_id,
                catalog_root_page_id,
                free_list_root_page_id,
                next_page_id,
                unix_seconds,
            };
            let mut encoded = encode_commit_meta(&meta);
            // A longer row is what a future format revision looks like from
            // here; the fixed prefix must still decode unchanged.
            encoded.extend_from_slice(&trailing);
            let decoded = decode_commit_meta(&encoded).unwrap();
            prop_assert_eq!(decoded.active_root_page_id, active_root_page_id);
            prop_assert_eq!(decoded.catalog_root_page_id, catalog_root_page_id);
            prop_assert_eq!(decoded.free_list_root_page_id, free_list_root_page_id);
            prop_assert_eq!(decoded.next_page_id, next_page_id);
            prop_assert_eq!(decoded.unix_seconds, unix_seconds);
        }
    }
}
