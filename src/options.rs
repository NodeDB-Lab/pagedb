//! `OpenOptions` — explicit memory budgets for a `Db` instance.
//!
//! Three budgets are hard limits that refuse the operation crossing them:
//! `scratch_bytes` (per-transaction spill arena), `mmap_view_scratch_bytes`
//! (decrypted `mmap_view` scratch), and `reader_stall_threshold_pages`
//! (deferred-free backlog). `buffer_pool_pages` and `segment_cache_pages` cap
//! their caches by eviction rather than by refusal: a clean, unpinned page is
//! evicted to stay within the count. Dirty pages are exempt from eviction
//! until they are flushed, so a single very large write transaction can hold
//! more than `buffer_pool_pages` resident between flushes.

use std::time::Duration;

use crate::crypto::CipherId;

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
/// | `mmap_view_scratch_bytes` | 0 (`mmap_view` refused) |
/// | `commit_history_retain` | `Count(1024)` |
/// | `reader_stall_threshold_pages` | 100_000 |
/// | `observer_retry_count` | 3 |
/// | `cipher` | `Aes256Gcm` |
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
    /// once, across every live view on this handle. Defaults to 0, which
    /// refuses every `mmap_view` call: mapping decrypted bytes is opt-in, so
    /// an embedder that wants it states a budget for it.
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
    /// [`DbStats`]: crate::DbStats
    pub metrics_enabled: bool,

    /// Maximum number of nonces the main-db Pager may issue between durable
    /// nonce-anchor writes.
    ///
    /// It bounds how far the counter may run ahead of the anchor recorded in the
    /// A/B header, not how much work an operation may do: a run that would
    /// exhaust the window rewrites the live header with a larger anchor and
    /// nothing else changed, then continues. A smaller budget therefore costs
    /// extra header writes on large operations, and a crash re-opens having
    /// skipped at most one budget's worth of counter values. Default: 1024.
    pub anchor_budget: u64,

    /// Cipher for a database this open *creates*.
    ///
    /// Ignored when the database already exists: every encrypted byte carries
    /// its own `cipher_id`, and an existing store is always read under the
    /// cipher its pages were written with, never under this setting. Choosing
    /// it here is therefore a one-time decision made at bootstrap — which is
    /// also why it is an open option rather than a runtime switch.
    pub cipher: CipherId,
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
            cipher: CipherId::Aes256Gcm,
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

    /// Set how far the main-db nonce counter may run ahead of the anchor in the
    /// durable header. A larger value trades a wider post-crash counter skip for
    /// fewer anchor writes during large operations. Default: 1024.
    #[must_use]
    pub fn with_anchor_budget(mut self, v: u64) -> Self {
        self.anchor_budget = v;
        self
    }

    /// Select the cipher used to create a new database. Has no effect on an
    /// open that finds an existing store.
    #[must_use]
    pub fn with_cipher(mut self, v: CipherId) -> Self {
        self.cipher = v;
        self
    }
}
