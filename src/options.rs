//! `OpenOptions` — explicit memory budgets for a `Db` instance.
//!
//! Every budget is advisory at this stage: `scratch_bytes` is the only
//! hard-enforced limit (spill arena cap). The buffer-pool and segment-cache
//! page counts are plumbed into `PagerConfig` but not yet enforced above the
//! Pager; `mmap_view_scratch_bytes` is wired up when the W slice lands.

use std::time::Duration;

/// Controls how many historical commit entries the commit-history index retains.
///
/// Pruning runs on every `WriteTxn::commit()`, but active readers always pin
/// their own commit — their entry is never removed regardless of policy.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainPolicy {
    /// Keep the newest `n` commit entries (excluding pinned reader entries).
    Count(u32),
    /// Keep entries whose recorded unix timestamp is within `d` seconds of now.
    /// Entries older than `now - d` are pruned (unless pinned by an active reader).
    Age(Duration),
    /// Never prune; keep every commit entry.
    Unbounded,
    /// **Pagedb extension beyond the architecture spec** (which defines
    /// only `Count` / `Age` / `Bytes` / `Unbounded`). Do not maintain the
    /// commit-history index at all. `WriteTxn::commit` skips the
    /// history-tree `CoW` + flush entirely (no per-commit insert, no
    /// pruning). The header's `commit_history_root_page_id` stays at zero.
    ///
    /// Selecting this disables every API that depends on commit history:
    /// - `Db::begin_read_at(commit_id)` — point-in-time reads
    /// - `Db::restore_from(commit_id)` — snapshot-restore by id
    /// - `apply_incremental` from a `base_commit` (Follower-mode replication)
    /// - `snapshot_to(since=Some(base))` — incremental snapshot exports
    ///
    /// Use only when the embedder will never need any of those APIs (e.g.
    /// pure ephemeral KV workloads, benchmarks against engines that don't
    /// ship an equivalent index). Default is `Count(1024)`, which conforms
    /// to the spec.
    Disabled,
}

impl Default for RetainPolicy {
    fn default() -> Self {
        Self::Count(1024)
    }
}

/// Memory budgets applied when opening a `Db`. Construct via
/// `OpenOptions::default()` and set individual budgets with the `with_*` builder
/// methods. Do not use struct-literal syntax; new fields may be added.
///
/// # Defaults
/// | Field | Default |
/// |---|---|
/// | `scratch_bytes` | 64 MiB |
/// | `buffer_pool_pages` | 1024 |
/// | `segment_cache_pages` | 64 |
/// | `mmap_view_scratch_bytes` | 0 (disabled) |
/// | `commit_history_retain` | `Count(1024)` |
/// | `reader_stall_threshold_pages` | 100_000 |
/// | `observer_retry_count` | 3 |
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct OpenOptions {
    /// Maximum total ciphertext (body + 16-byte AEAD tag) written to the
    /// per-`WriteTxn` spill scratch file before the budget is exhausted and
    /// `PagedbError::Quota { kind: QuotaKind::ScratchPages, … }` is returned.
    pub scratch_bytes: usize,

    /// Number of 4 KiB / 8 KiB / 16 KiB pages held in the Pager's buffer pool.
    pub buffer_pool_pages: usize,

    /// Number of pages held in the per-segment reader LRU cache.
    pub segment_cache_pages: usize,

    /// Maximum bytes of already-decrypted scratch that `mmap_view` may map at
    /// once. Set to 0 (disabled) until the W slice lands.
    pub mmap_view_scratch_bytes: usize,

    /// How many historical commit entries the commit-history index retains.
    /// Pruning happens at every commit. Active readers always pin their own
    /// commit, protecting it from pruning.
    pub commit_history_retain: RetainPolicy,

    /// Size of the deferred-free queue (in pages) at which the
    /// `ReaderStallPolicy` fires. When the queue grows beyond this value and
    /// reader pins are preventing a drain, the configured policy is applied.
    /// Default: `100_000`.
    pub reader_stall_threshold_pages: u64,

    /// Number of AEAD-failure retries for Observer-mode page reads before
    /// surfacing the error. Each retry has a 10 ms backoff. Default: 3.
    pub observer_retry_count: u32,

    /// Track buffer-pool hit/miss counts (visible via [`DbStats`]). Adds two
    /// `AtomicU64` `fetch_add` per main-db page read on the hot path; disable
    /// when the embedder doesn't read [`DbStats`]. Default: `true`.
    ///
    /// [`DbStats`]: crate::observability::DbStats
    pub metrics_enabled: bool,

    /// Maximum number of nonces the main-db Pager may issue between A/B
    /// header commits. A single write transaction cannot produce more than
    /// this many newly-encrypted pages — exceed it and the txn aborts. Large
    /// bulk loads need a larger budget. Default: 1024.
    pub anchor_budget: u64,

    /// **Pagedb extension beyond the architecture spec.** When `true` and no
    /// readers are pinned at commit time, skip persisting freed pages into
    /// the deferred-free queue / persistent free-list. The pages become
    /// **orphan pages** in `main.db` — physically allocated but unreferenced
    /// — and can only be reclaimed by [`Db::compact`].
    ///
    /// Trade-off:
    /// - **Pro**: Eliminates one catalog-tree `CoW` per commit. Big
    ///   single-put write-latency win (~75µs on a 4 KiB page DB).
    /// - **Con**: `main.db` grows monotonically during no-reader phases.
    ///   Embedders MUST schedule periodic [`Db::compact`] to reclaim space,
    ///   or accept unbounded growth.
    ///
    /// Default: `false` (spec-conformant; every freed page is tracked).
    ///
    /// Use cases that should enable this:
    /// - Benchmarks measuring against engines without an equivalent free-list
    /// - Ephemeral / cache-like deployments that periodically compact or
    ///   rebuild
    /// - Workloads where the embedder can prove the file is short-lived
    ///
    /// Use cases that should NOT enable this:
    /// - Long-running write-heavy stores without compaction infrastructure
    /// - Anything where unbounded `main.db` growth is a problem
    pub skip_freelist_persistence_when_no_readers: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            scratch_bytes: 64 * 1024 * 1024,
            buffer_pool_pages: 1024,
            segment_cache_pages: 64,
            mmap_view_scratch_bytes: 0,
            commit_history_retain: RetainPolicy::default(),
            reader_stall_threshold_pages: 100_000,
            observer_retry_count: 3,
            metrics_enabled: true,
            anchor_budget: crate::crypto::nonce::DEFAULT_ANCHOR_BUDGET,
            // Default: spec-conformant. Embedders that want the fast path
            // explicitly opt in.
            skip_freelist_persistence_when_no_readers: false,
        }
    }
}

impl OpenOptions {
    /// Set the maximum bytes for the per-`WriteTxn` spill scratch file.
    #[must_use]
    pub fn with_scratch_bytes(mut self, v: usize) -> Self {
        self.scratch_bytes = v;
        self
    }

    /// Set the number of pages held in the buffer pool.
    #[must_use]
    pub fn with_buffer_pool_pages(mut self, v: usize) -> Self {
        self.buffer_pool_pages = v;
        self
    }

    /// Set the number of pages held in the per-segment reader LRU cache.
    #[must_use]
    pub fn with_segment_cache_pages(mut self, v: usize) -> Self {
        self.segment_cache_pages = v;
        self
    }

    /// Set the maximum bytes of decrypted `mmap_view` scratch.
    #[must_use]
    pub fn with_mmap_view_scratch_bytes(mut self, v: usize) -> Self {
        self.mmap_view_scratch_bytes = v;
        self
    }

    /// Set the commit-history retention policy.
    #[must_use]
    pub fn with_commit_history_retain(mut self, v: RetainPolicy) -> Self {
        self.commit_history_retain = v;
        self
    }

    /// Set the deferred-free backlog threshold (pages) at which the reader
    /// stall policy fires.
    #[must_use]
    pub fn with_reader_stall_threshold_pages(mut self, v: u64) -> Self {
        self.reader_stall_threshold_pages = v;
        self
    }

    /// Set the number of AEAD-failure retries for Observer-mode reads.
    #[must_use]
    pub fn with_observer_retry_count(mut self, v: u32) -> Self {
        self.observer_retry_count = v;
        self
    }

    /// Enable/disable buffer-pool hit/miss tracking. Disabling skips two
    /// atomic `fetch_add` per page read on the hot path.
    #[must_use]
    pub fn with_metrics_enabled(mut self, v: bool) -> Self {
        self.metrics_enabled = v;
        self
    }

    /// Set the main-db Pager's nonce anchor budget (max nonces per txn).
    /// Bulk loads need a larger value. Default: 1024.
    #[must_use]
    pub fn with_anchor_budget(mut self, v: u64) -> Self {
        self.anchor_budget = v;
        self
    }

    /// Opt into the no-readers fast-free path. See
    /// [`Self::skip_freelist_persistence_when_no_readers`] for the trade-off.
    /// Embedders that enable this **must** schedule periodic
    /// [`Db::compact`](crate::Db::compact) to reclaim orphan pages.
    #[must_use]
    pub fn with_skip_freelist_persistence_when_no_readers(mut self, v: bool) -> Self {
        self.skip_freelist_persistence_when_no_readers = v;
        self
    }
}
