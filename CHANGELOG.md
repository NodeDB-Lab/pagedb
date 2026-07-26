# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first stable release. Pre-releases are published as `0.1.0-beta.N`; the
entries below describe `0.1.0` as a whole rather than deltas against a shipped
version, since none exists yet.

### Added

- **B+ tree surface** — sorted `bytes → bytes` store with copy-on-write shadow
  paging, A/B headers, ACID transactions, range scans, monotonic append, and
  bulk load.
- **Segment File API** — engine-owned, append-mostly, atomically sealed
  encrypted files for formats that own their own layout (vectors, columnar
  blocks, FTS postings, R-trees).
- **Encrypted pager** — every persistent page is authenticated; AES-256-GCM and
  ChaCha20-Poly1305 cipher dispatch with per-page `cipher_id` for cipher
  agility. SIEVE page cache with bounded memory budgets.
- **Key hierarchy** — KEK → MK → DEK derivation, stateful nonce generation with
  a durable anchor (nonce reuse impossible under one key), `zeroize` on all key
  material.
- **Realm isolation** — `RealmId` bound into AEAD AAD on every persistent page;
  misrouted reads fail tag verification. Per-realm quotas.
- **Cross-platform VFS** — Linux (`io_uring`), Windows (IOCP), macOS/iOS
  (Grand Central Dispatch), Android, WASM/OPFS, and WASI backends, plus a
  tokio thread-pool fallback and an in-memory backend, with format-bit identity
  across targets. Backends may complete a positional read or write in several
  calls; PageDB finishes the caller's whole buffer before treating authenticated
  metadata as present or durable.
- **Snapshots** — `snapshot_to`, `restore_from`, and incremental apply, each
  authenticated against the exact state its manifest describes. Destinations
  must be empty; malformed or incomplete artifacts fail closed.
- **Recovery** — open-flow GC, apply-journal replay, deep-walk `fsck`, and the
  `pagedb-fsck` binary.
- **Online rekey** — rekey the database under a new key with mixed-cipher and
  mixed-epoch page coexistence (no full-file migration).
- **Handle modes** — `Standalone`, `Follower`, `ReadOnly`, and `Observer`.
- **Failures report themselves** — an unreadable free-list chain, main file, or
  segment catalog fails `stats()` instead of reporting zero; compaction never
  skips a catalog entry whose file it cannot open; segment open distinguishes a
  missing file from a permission or backend error; and only genuine contention
  is reported as contention. Persisted named-counter rows are validated at open,
  and commit-history keys are rejected unless exactly eight bytes.

### Known limitations

- Pre-1.0: the on-disk format may change between minor versions until 1.0.
- Single-writer per database; multi-writer cross-process is not supported.
- Writes carry per-page AEAD and copy-on-write overhead; for throughput-bound
  plaintext KV workloads a generic store may be faster.
- An incremental snapshot cannot always be applied: if the producer recycled a
  page the follower's own free-list chain or commit-history tree still hosts,
  apply reports `PagedbError::SnapshotBasePageReused` and the follower needs a
  full snapshot or a nearer base commit.
