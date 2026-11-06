//! `OpenOptions` — explicit memory budgets for a `Db` instance.
//!
//! Three budgets are hard limits that refuse the operation crossing them:
//! `scratch_bytes` (per-transaction spill arena), `mmap_view_scratch_bytes`
//! (decrypted `mmap_view` scratch), and `reader_stall_threshold_pages`
//! (deferred-free backlog). `buffer_pool_pages` and `segment_cache_pages` cap
//! their caches by eviction rather than by refusal: a clean, unpinned page is
//! evicted to stay within the count. A cache exceeds its count only while every
//! entry is dirty or pinned. A transaction's dirty pages and pinned pages can
//! exceed the budget. The cache returns to the count once they are flushed or
//! released.

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
    /// only `Count` / `Age` / `Bytes` / `Unbounded`). Keep no commit-history
    /// rows. `WriteTxn::commit` writes no row and prunes nothing.
    ///
    /// Selecting this on a store that holds rows removes them:
    /// - The handle refuses them at once.
    /// - The first `WriteTxn::commit`, `rekey_db`, or `apply_incremental` frees
    ///   the history tree and writes root zero. No later policy gets them back.
    /// - A read-only or observer handle changes nothing. Reopening under another
    ///   policy before any such write still finds them.
    /// - Until the removal is durable, the rows still hold back free-page reuse.
    ///   A crash cannot leave them naming overwritten pages.
    ///
    /// These APIs serve the latest commit only, and return
    /// [`PagedbError::CommitGone`](crate::PagedbError::CommitGone) for any other:
    /// - `Db::begin_read_at(commit_id)` — point-in-time reads
    /// - `Db::snapshot_incremental_to(base, ..)` — incremental snapshot exports
    ///
    /// `apply_incremental` still works, because its base is the follower's latest
    /// commit. `snapshot_to` and `restore_from` copy the store as it stands.
    ///
    /// A header holding this policy's tag beside a non-zero history root proves
    /// an earlier release left those rows unmaintained. They count as gone under
    /// every policy, and a writable handle removes them at its first write.
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

    /// Number of pages held in the SIEVE cache for apply-journal pages.
    /// Segment file reads do not use this cache.
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
    /// extra header writes on large operations. Default: 1024.
    ///
    /// A value above 1,048,576 (2^20) issues under 1,048,576. Each open that
    /// writes a header skips that many counter values, whatever this value is.
    /// The first flush after an open writes a header before it seals a page.
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

    /// Set the number of pages held in the shared SIEVE cache for segment
    /// files. The same cache also holds apply-journal pages.
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
    /// durable header. A larger value means fewer anchor writes during large
    /// operations. A value above 1,048,576 (2^20) issues under 1,048,576.
    /// Default: 1024.
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
