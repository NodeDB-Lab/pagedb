# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Page allocation no longer rescans the freed list.** `allocate_page` decided in-session reuse eligibility per call, scanning every page freed so far and, for each, every page drawn from the shared free-page cache — both `Vec<u64>`, so the membership test was linear. Since the reuse threshold is the session-start `next_page_id`, every page freed during a transaction fell below it and took the slow arm, making allocation quadratic in the pages a flush touches: a flush large enough would occupy a core indefinitely without completing. Eligibility is now decided once, when the page is freed, and allocation is a pop. Behaviour is unchanged — both inputs to the decision are monotonic within a session, so deciding early is equivalent.

## [0.1.0] - 2026-07-28

The first release. Pre-releases were published as `0.1.0-beta.N`; the entries below describe `0.1.0` as a whole rather than deltas against a shipped version, since none exists yet.

### Added

- **B+ tree surface** — sorted `bytes → bytes` with copy-on-write shadow paging, A/B headers, ACID transactions, range scans, monotonic append, and bulk load. Reads return `Bytes` borrowed from the page cache; scans are bounded (`scan_from`, `scan_prefix_from`) or materialising.
- **Segment File API** — engine-owned, append-mostly, atomically sealed encrypted files for formats that own their own layout (vectors, columnar blocks, FTS postings, R-trees).
- **Encrypted pager** — every persistent page is authenticated; AES-256-GCM and ChaCha20-Poly1305 with per-page `cipher_id` for cipher agility. SIEVE page cache with bounded memory budgets.
- **Key hierarchy** — KEK → MK → per-`(realm, file)` DEK/IK, stateful nonce generation with a durable anchor, `zeroize` on all key material.
- **Realm isolation** — `RealmId` bound into AEAD AAD on every persistent page and recorded in the `main.db` header. Per-realm quotas.
- **Cross-platform VFS** — Linux (`io_uring`), Windows (IOCP), macOS/iOS (Grand Central Dispatch), Android, WASM/OPFS and WASI backends, plus a tokio thread-pool fallback and an in-memory backend, with format-bit identity across targets. On Linux the backend is chosen at run time: a kernel that refuses an `io_uring` ring falls back to the thread pool with a warning instead of failing the open. All native backends share one advisory-lock implementation, so processes on different backends still exclude each other on one store.
- **Snapshots** — `snapshot_to`, `restore_from`, and incremental apply, each authenticated against the state its manifest describes. Destinations must be empty; malformed or incomplete artifacts fail closed.
- **Recovery** — open-flow GC, apply-journal replay, deep-walk `fsck`, and the `pagedb-fsck` binary.
- **Online rekey** — rekey under a new key with mixed-cipher and mixed-epoch page coexistence; no full-file migration.
- **Handle modes** — `Standalone`, `Follower`, `ReadOnly`, and `Observer`.
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
