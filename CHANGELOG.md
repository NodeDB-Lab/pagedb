# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Reader observability** — `DbStats` gains `oldest_reader_commit_id`, `oldest_reader_age_ms` (both `None` when no reader is registered) and `tracked_readers_non_abortable` (`u32`), so a long-lived read transaction that holds back free-page reuse is visible from `Db::stats()`.
- **Compaction decline flag** — `CompactStats` and `CompactProgress` gain `declined_readers_pinned` (`bool`). `compact_now` and `compact_step` set it when a registered reader pins the page range and the pass does not run, so a caller can tell that result apart from a pass that found nothing to reclaim. Every count is zero in both cases, and `CompactProgress::more_work` stays `false`.

### Changed

- **Mode gates on two store writes** — `set_realm_quotas` now returns `WrongMode` on `Follower`, `ReadOnly`, and `Observer` handles. `gc_now` now returns `WrongMode` on `ReadOnly` and `Observer` handles.
- **MSRV is Rust 1.88** — earlier toolchains did not build, because the crate and `faultbox` use let-chains.
- **Visibility gate on metadata walks** — `Db::stats`, `list_segments`, `open_segment`, and `realm_quotas` hold the visibility gate for their walk. They wait during a compaction or an apply, and a commit's publication waits for them. `run_deep_walk` holds the writer lock for its whole walk. `page_provenance` with a busy writer reports the free list as an unwalkable gap.
- **Page cache invariant error** — new `PagedbError::PageCacheStateInvalid` replaces a panic when the page cache breaks an invariant. The cache latches the error, and every later operation on that cache reports it. Close and reopen the handle to clear it. No fault is known in the store files.
- **Free pages after a rekey** — a free page below the reclamation floor reads as a zeroed `Free` page on disk after a rekey.

### Fixed

- **Pinned follower readers** — `apply_incremental` now returns `ApplyBlockedByPinnedReader`, before it changes `main.db`, when its delta rewrites a page a reader pinned before the base commit can reach. That reader previously read authenticated bytes from the later commit. Retry the same delta after the reader finishes.
- **Commit-history retention after a reopen** — with `RetainPolicy::Count(n)`, the first commit after a reopen pruned one commit too many and kept `n - 1`.
- **Relocated commit history on a small buffer pool** — an apply that relocated a commit-history tree larger than the buffer pool flushed part of it to the live `main.db`. The published image then lacked those pages.
- **Historical reads after a rekey** — `rekey_db` tagged the catalog pages it superseded with the latest commit, so a later commit could recycle them while that commit's retained row still named them. `begin_read_at` then failed with `ChecksumFailure`. New entries carry the next commit id. Entries already on a store's free list keep their old tag, so such a page stays exposed until that row is pruned. The on-disk format does not change.
- **Historical reads on a follower** — `apply_incremental` carried commit-history rows whose pages its delta overwrote, so `begin_read_at` admitted a reader over bytes from a later commit. An apply now prunes the newest such row and every older row, durably, and `begin_read_at` reports `CommitGone` for them. Surviving rows read their own values. An apply on a follower with retained rows now reads each retained page the base does not reach once.
- **Buffer pool budget** — `buffer_pool_pages` and `segment_cache_pages` are now honoured. The cache evicts back to its count after a flush, an abort, or a last unpin. Before, one large transaction kept the pool above budget for the life of the handle. Dirty and pinned pages can still exceed the budget until flushed or released. A large write now misses the cache more often, because the tree no longer stays cached past the budget.
- **Quadratic eviction** — dirty pages leave the eviction list. A large transaction no longer walks them for each clean-page eviction.
- **Lost writes from a racing read** — a read miss that completed after a write replaced the dirty page with older bytes, and a flush could persist them. The resident page now wins. The reads that register no reader cannot run during a swap.
- **Stale file handle** — a read during a compaction or apply swap could keep the replaced file open. Later reads then used the old file.
- **Rekey after an abort** — aborted pages stayed in the cache as clean pages. A rekey could hit one, fail with `ChecksumFailure`, and poison the handle. An abort now removes unpinned dirty pages.
- **Rekey past a torn free page** — a free page that no retained root or reader can name no longer stops a rekey or its resume. A torn page a retained root can reach still fails, and its bytes stay on disk as evidence.
- **`dirty_pages` in `DbStats`** — it counted only one segment id. It now counts every entry.

## [0.1.0] - 2026-10-15

The first stable release. The entries describe `0.1.0` as a whole. The `0.1.0-beta.N` pre-releases have no entries of their own.

### Added

- **B+ tree surface** — sorted `bytes → bytes` with copy-on-write shadow paging, A/B headers, ACID transactions, range scans, monotonic append, and bulk load. Reads return `Bytes` borrowed from the page cache; scans are bounded (`scan_from`, `scan_prefix_from`) or materialising.
- **Segment File API** — engine-owned, append-mostly, atomically sealed encrypted files for formats that own their own layout (vectors, columnar blocks, FTS postings, R-trees).
- **Encrypted pager** — every persistent page is authenticated; AES-256-GCM and ChaCha20-Poly1305 with per-page `cipher_id` for cipher agility. SIEVE page cache with bounded memory budgets.
- **Key hierarchy** — KEK → MK → per-`(realm, file)` DEK/IK, stateful nonce generation with a durable anchor, `zeroize` on all key material.
- **Realm isolation** — `RealmId` bound into AEAD AAD on every persistent page and recorded in the `main.db` header. Per-realm quotas.
- **Cross-platform VFS** — Linux (`io_uring`), Windows (IOCP), macOS/iOS (Grand Central Dispatch), Android, WASM/OPFS and WASI backends, plus a tokio thread-pool fallback and an in-memory backend, with format-bit identity across targets. On Linux the backend is chosen at run time: a kernel that refuses an `io_uring` ring falls back to the thread pool with a warning instead of failing the open. All native backends share one advisory-lock implementation, so processes on different backends still exclude each other on one store.
- **Snapshots** — `snapshot_to`, `restore_from`, and incremental apply, each authenticated against the state its manifest describes. Destinations must be empty; malformed or incomplete artifacts fail closed.
- **Recovery** — open-flow GC, apply-journal replay, deep-walk `fsck`, and the `pagedb-fsck` binary.
- **Online rekey** — rekey under a new key with mixed-cipher and mixed-epoch page coexistence; no full-file migration. A rotation whose source epoch is still pinned by a reader defers retiring it and completes the retirement once the reader set drains — including when the last reader leaves during the deferral itself, so the superseded master key never stays leasable behind an `Ok(())`. A retirement that cannot be taken yet stays queued for the next attempt without holding up the others.
- **Handle modes** — `Standalone`, `Follower`, `ReadOnly`, and `Observer`, each holding its own sentinel. A snapshot or restored directory shares its source's identity, so it opens only as `ReadOnly` or as a `Follower` (`open_follower`, `promote_to_follower`), and a `Standalone` open reports `RestoredNotPromoted`. `rekey_into_writer` forks it into an independent `Standalone` writer under a fresh identity.
- **Open refusals name the parameter, not the store** — `KeyMismatch`, `PageSizeMismatch`, and `RealmMismatch`, each decided before anything is read or written, and none reported as corruption.
- **Failures report themselves** — an unreadable free-list chain, main file, or segment catalog fails `stats()` instead of reporting zero; compaction never skips a catalog entry whose file it cannot open; segment open distinguishes a missing file from a permission or backend error; and only genuine contention is reported as contention. Persisted named-counter rows are validated at open, and commit-history keys are rejected unless exactly eight bytes.

### Security

- Threat model documented in the README; disclosure policy in `SECURITY.md`.
- Data keys are scoped per file, so no two files share a nonce space.
- `io_uring`: an error mid-submission no longer frees a transfer buffer the kernel may still be writing into.
- `pagedb-fsck` requires an explicit KEK — no all-zero default.
- Diagnostic reports redact embedder-chosen segment names.

### Known limitations

- Pre-1.0: the API may break in a minor bump. The on-disk format is frozen for the `0.1.x` line and any later format change ships a migrator — see `VERSIONING.md`. Stores written by a `0.1.0-beta` pre-release are not readable by `0.1.0`.
- pagedb detects tampering, not reversion: an attacker who can write to the store files can substitute an older genuine ciphertext and it will authenticate. Freshness belongs above pagedb.
- `main.db` cannot be reconstructed from `seg/` — back the directory up as a unit.
- Single-writer per database; multi-writer cross-process is not supported.
- Writes carry per-page AEAD and copy-on-write overhead; for throughput-bound plaintext KV workloads a generic store may be faster.
- Applying an incremental snapshot stages a full copy of `main.db` alongside the original, so a follower needs room for two copies during an apply.

[Unreleased]: https://github.com/NodeDB-Lab/pagedb/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NodeDB-Lab/pagedb/releases/tag/v0.1.0
