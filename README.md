<div align="center">

<h1>pagedb</h1>

<h3>An encrypted, portable, embedded page store for Rust.</h3>

<p>
  Pure Rust, async-native, no C dependencies, no <code>mmap</code> of encrypted bytes.
  One cryptographic substrate under two purpose-built surfaces — a CoW B+ tree and an
  engine-owned segment file API. Runs on Linux, macOS, Windows, iOS, Android, browsers
  (WASM/OPFS), and WASI, with format-bit-identity across every target.
</p>

<p>
  <a href="https://docs.rs/pagedb"><strong>API Docs</strong></a>
  ·
  <a href="https://crates.io/crates/pagedb"><strong>crates.io</strong></a>
  ·
  <a href="#position-in-the-stack"><strong>Architecture</strong></a>
  ·
  <a href="#benchmarks"><strong>Benchmarks</strong></a>
  ·
  <a href="#faq--questions-people-actually-ask"><strong>FAQ</strong></a>
</p>

<p>
  <a href="https://github.com/nodedb-lab/pagedb/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/nodedb-lab/pagedb/ci.yml?branch=main&label=ci" alt="CI status">
  </a>
  <a href="https://crates.io/crates/pagedb">
    <img src="https://img.shields.io/crates/v/pagedb" alt="crates.io version">
  </a>
  <a href="https://crates.io/crates/pagedb">
    <img src="https://img.shields.io/crates/d/pagedb?label=downloads" alt="crates.io downloads">
  </a>
  <a href="https://docs.rs/pagedb">
    <img src="https://img.shields.io/docsrs/pagedb" alt="docs.rs">
  </a>
  <a href="https://github.com/nodedb-lab/pagedb#license">
    <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License">
  </a>
  <a href="https://github.com/nodedb-lab/pagedb/stargazers">
    <img src="https://img.shields.io/github/stars/nodedb-lab/pagedb?style=social" alt="GitHub stars">
  </a>
</p>

</div>

## What is pagedb?

pagedb is **not a KV store.** It is a page store that exposes **two purpose-built surfaces** on top of one cryptographic substrate:

| Surface              | What it is                                                           | Best for                                                                                                                            |
| -------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **B+ Tree**          | Sorted `bytes → bytes` tables. CoW shadow paging. ACID transactions. | Documents, secondary indexes, edge stores, KV, catalog, counters, op-logs.                                                          |
| **Segment File API** | Engine-owned, append-mostly, sealable files of encrypted pages.      | Vector / columnar / timeseries / FTS / graph-CSR / spatial / array. Anything with its own block format, codec, or zero-copy layout. |

Both surfaces share the same Pager (cache + AEAD) and VFS, and inherit portability, encryption, durability, and bounded-memory guarantees from Layer 1.

## Why it exists

Stacking a multi-model database on a generic KV abstraction (the SurrealDB-on-RocksDB pattern) caps every engine at the KV layer's worst case. Vector search becomes a tree walk per neighbor. Columnar scans lose locality. FTS posting lookups pay a B-tree descent per term.

Rolling per-engine storage duplicates encryption, durability, and portability badly. Building yet another generic KV solves nothing.

pagedb's answer: **one substrate, two surfaces.** Engines that want their own format (HNSW, ALP/FastLanes, posting lists, R-trees, CSR arrays) get direct, encrypted, durable, portable access to it. The B+ tree handles everything sparse and sorted.

## Highlights

- **Encryption-first.** AES-256-GCM or ChaCha20-Poly1305 by default; plaintext+MAC opt-in. **Integrity is always on** — no mode writes bytes without authentication. Per-page `cipher_id` for cipher agility (PQ-ready).
- **Async all the way down.** Tokio on native, `gloo-worker` on WASM/OPFS. No blocking calls in async paths.
- **WASM / OPFS first-class.** Browsers run pagedb with the same code that runs on Linux. Real durable encrypted storage in a tab.
- **Parallel ingest.** One B+ tree writer + **unlimited concurrent segment writers**. A timeseries firehose, a columnar build, an FTS append, and a metadata commit can all run in parallel.
- **Format-portable.** A directory created on any target opens byte-identically on every other target. Identity-keyed segment paths keep UTF-8 names out of the filesystem layer.
- **Bounded memory.** Hard cap + CLOCK-Pro eviction. No mmap surprises, no uncapped OS page cache.
- **Realms.** Per-realm DEK + AAD-bound `RealmId` for cryptographic multi-tenancy within one DB.
- **Online rekey, online compact, incremental snapshots.** Throttled, cancellable, resumable.
- **No `unsafe`** outside the VFS and the opt-in `mmap_view` over decrypted scratch.

## Position in the stack

```
┌────────────────────────────────────────────────────────────┐
│  Embedder (engines: vector, columnar, FTS, graph, …)       │
├──────────────────────────┬─────────────────────────────────┤
│  Layer 3a: B+ Tree       │  Layer 3b: Segment File API     │
│  sorted bytes→bytes,     │  append-mostly encrypted files, │
│  ACID, range scans       │  engine-owned format            │
├──────────────────────────┴─────────────────────────────────┤
│  Layer 2: Pager  (cache, AEAD, prefetch, vectored I/O)     │
├────────────────────────────────────────────────────────────┤
│  Layer 1: Vfs    (File trait, Direct I/O)                  │
├────────────────────────────────────────────────────────────┤
│  Platform: io_uring │ IOCP │ dispatch_io │ OPFS Worker │ … │
└────────────────────────────────────────────────────────────┘
```

## Integrity inspection

`pagedb-fsck` opens an existing store in frozen read-only mode. Add `--deep` to
run a full authenticated structural walk:

```bash
cargo run --bin pagedb-fsck -- <path> --deep \
  --realm 00000000000000000000000000000000 <64-hex-character-kek>
```

The KEK may instead come from `PAGEDB_KEK` and defaults to all zeros. The realm
defaults to all ones; nodedb-lite stores use the all-zero realm shown above.
Add `--page-size` for a store created at anything other than 4096 bytes, and
`--help` for the full grammar. Inspection disables commit-history retention and
does not rewrite authoritative `main.db` or segment bytes.

Arguments are validated before the store is touched, and each failure class
gets its own exit code so a caller can tell them apart:

| Code | Meaning                                                           |
| ---: | ----------------------------------------------------------------- |
|    0 | Opened cleanly; with `--deep`, the report was clean               |
|    1 | An integrity problem was found                                    |
|    2 | The command line was invalid; the store was never opened          |
|    3 | The store could not be opened, or the report could not be written |

## Benchmarks

Measured on native NVMe, AES-NI host, single thread, via `fluxbench`. Reproduce the
PageDB-owned benches and the isolated cross-engine suite with:

```bash
cargo bench --bench segment
cargo bench --bench compaction
cargo bench --bench authenticated_node_read
cargo bench --bench read_path
cargo bench --bench write_path
cargo bench -p pagedb-engine-comparison --bench btree
cargo bench -p pagedb-engine-comparison --bench comparison
```

`authenticated_node_read` evicts the main-page cache before each lookup through
a multi-level tree, measuring cold authenticated leaf/internal kind discovery
without resolving or compiling an external database engine. `read_path`
decomposes a warm lookup into transaction open/close versus tree descent.
`write_path` reports per-row allocation totals and per-row cost against
transaction size.

The comparison suite is a non-default workspace package under
[`benchmarks/engine-comparison`](./benchmarks/engine-comparison). Normal
`cargo test` and `cargo nextest` runs for the `pagedb` package therefore do not
resolve or compile RocksDB, redb, or SQLite.

Both cross-engine suites disable pagedb's commit-history index. redb has no
equivalent, so retaining it would compare different feature surfaces.

### vs. redb (B+ tree, in-process, 1 000-key tree)

| Workload                        |     pagedb |    redb | vs redb          |
| ------------------------------- | ---------: | ------: | ---------------- |
| Point get (per-txn, AEAD)       |     491 ns |  374 ns | 1.31× slower     |
| Batched insert (1 000 keys/txn) | **663 µs** | 1.76 ms | **2.66× faster** |
| Per-txn insert (in-memory)      |    25.2 µs | 13.0 µs | 1.94× slower     |
| Per-txn insert (file, AEAD on)  |   115.7 µs | 13.0 µs | 8.9× slower      |

AEAD overhead on reads is **~1.00×** (491 ns AEAD vs 489 ns plaintext+MAC) —
encryption really is free on hot reads, because the buffer pool holds decrypted
plaintext and a warm hit re-authenticates nothing.

### vs. redb / RocksDB / SQLite (full comparison suite, 100 000 rows)

| Workload                       |     pagedb |       redb |    RocksDB |     SQLite |
| ------------------------------ | ---------: | ---------: | ---------: | ---------: |
| Random point read              |     931 ns |     902 ns | **851 ns** |     9.9 µs |
| Range scan (10 entries)        |     3.6 µs | **1.7 µs** |     2.2 µs |    28.4 µs |
| Individual write (fsync-bound) |   184.5 µs |    28.2 µs | **4.9 µs** |    51.3 µs |
| Batch write (1 000 keys/txn)   |    9.61 ms |    3.70 ms | **1.95 ms** |    4.94 ms |
| Bulk load (100 000 rows/txn)   |     203 ms | **128 ms** |     289 ms |     176 ms |
| Sorted bulk load               | **109 ms** |     116 ms |     158 ms |     100 ms |

**Reads and bulk load are competitive; single-key writes trail.** Point reads
are level with redb and RocksDB on a 100 000-row set; range scans are ~2×
behind redb. Bulk load is 1.6× behind redb and ahead of RocksDB, and sorted
bulk load edges ahead of redb. The gap is the fsync-bound single-key commit,
where every transaction pays AEAD on each dirty page, a CoW shadow-page A/B
header swap, and per-realm AAD binding — none of which redb or RocksDB carry.
Batching amortises it; group-commit tuning and vectored fsync are the remaining
headroom.

Figures are the fastest observed run of several, on a shared host. Contention
only ever adds time, so the minimum is the closest estimate of what the code
itself costs; averaging over a loaded run inflates every engine, by amounts
that differ between them.

### Segment writer (append + seal)

| Path                            |       time | Notes                               |
| ------------------------------- | ---------: | ----------------------------------- |
| Raw AES-GCM only (memory)       |   300.7 µs | baseline: encryption cost alone     |
| **pagedb `append_seal`**        | **560.1 µs** | full path: write, seal, fsync, link |
| Raw `tokio::fs` write + AES-GCM |    1.40 ms | what you'd write yourself, badly    |

pagedb's segment writer adds **~1.86× over raw AEAD** but is **2.5× faster than a hand-rolled `fs::write` + AES-GCM** baseline — because pagedb batches, vectorizes, and uses the platform's best async primitive.

### Read-path decomposition

| Step                              |   time |
| --------------------------------- | -----: |
| `begin_read` + drop               | 141 ns |
| Warm `get` (transaction reused)   | 369 ns |
| Warm `get` (one transaction each) | 434 ns |
| Cold authenticated node read      | 6.8 µs |
| Dense repack (compaction)         | 306 µs |

A warm `get` allocates nothing: the value is a slice of the cached page, not a
copy of it.

---

## FAQ — questions people actually ask

### "Why not just use SQLite / redb?"

Pick **SQLite** if SQL fits your data model. Decades of fuzzing, every binding, real DBA tools. Stop reading.

Pick **redb** if you need a fast pure-Rust KV on native, don't need encryption, don't need WASM, and don't need engine-owned segment files. It's leaner and more mature than pagedb.

Pick **pagedb** when some intersection of these matters: **WASM/OPFS** (redb can't), **encryption-or-integrity as a default** (neither has), **engine-owned segment files** (the multi-model story neither offers), **parallel ingest across engines**, **pure Rust + async + bounded memory**.

### "Is pagedb production-ready?"

**No, not yet.** pagedb is new. SQLite has 24+ years of fuzzing and billions of devices behind it. redb has ~3 years. pagedb has neither. The design avoids known footguns (A/B headers, cipher agility, explicit reader-stall policy, no mmap of encrypted bytes), but newness is newness — there is no substitute for years of usage. Use it for projects where you can absorb that risk, or wait.

### "Why are writes slower than redb?"

Every pagedb commit pays for:

1. **AEAD encrypt on every dirty page** (~sub-µs each on AES-NI, but it adds up).
2. **CoW shadow paging + A/B header swap** — two header writes per commit, both authenticated.
3. **Per-realm AAD binding** on every page (cross-tenant misroute protection at runtime).
4. **Async I/O** — every write goes through the runtime, not a blocking syscall.

redb skips all of this. The trade is deliberate, not a bug. Reads come out level
with redb and bulk load is competitive; the cost lands on the fsync-bound
single-key commit, since all four items are paid per transaction. Batch your
writes and it amortises.

### "Why is there no mmap of encrypted bytes?"

Two reasons. First, you can't AEAD-decrypt bytes the OS faults into your address space without your code seeing them — the encryption boundary would be wrong. Second, OPFS doesn't have mmap, and pagedb wants one code path across native and browser. We claw the performance back with an explicit user-space buffer pool, vectored I/O, prefetch, and group commit. `mmap_view` exists for native engines that need zero-copy access — but it's over a _transient decrypted scratch file_ whose key is destroyed at view drop.

### "Can multiple processes write?"

No. One writer process + many read-only processes (SQLite-WAL-style). Multi-writer is an explicit non-goal — if you need it, put your writer behind RPC. Multi-process _reads_ matter on iOS (app + share extension), Android (app + content provider), macOS (app + helper) and are supported.

### "What about no_std / microcontrollers?"

Out of scope. The async runtime, AEAD context, and buffer pool put the floor at hundreds of KB of RAM and a real OS. Use something else.

### "What's a 'realm'?"

An opaque cryptographic isolation scope inside one DB. Each realm has its own DEK (AEAD modes) and is bound into the AAD of every page it owns, so a misrouted read fails tag verification at runtime. What a realm _means_ — tenant, user, device, database — is the embedder's call. pagedb doesn't care.

### "Why a directory instead of a single file?"

Because each engine owns its own segment files. A single file would force every engine's bytes through one B-tree (the SurrealDB-on-RocksDB problem we're explicitly solving) or invent an in-file sub-filesystem (badly). SQLite is also effectively a directory once you count `-wal` and `-shm`. If you need single-file ergonomics, tar the directory.

### "How does encryption opt-out work?"

`CipherPreference::PlaintextIntegrityOnly` at open time. The mode is recorded in the file header so any auditor can verify which mode a deployed file uses. **Integrity stays on** — corruption detection is non-negotiable. Use this for app config, game saves, public-data caches, dev tooling — anywhere you don't have a confidentiality threat model but still want corruption detection cheap.

### "Can I migrate from redb?"

The API surface is intentionally redb-shaped. The lift is mostly sync→async — existing call sites need `.await`, and a thin adapter wrapping `pagedb::Db` + a `RealmId` lets you keep most call-site shape (`begin_write` / `open_table` / `commit` map 1:1).

### "When should I _not_ use pagedb?"

- Your data fits SQL → SQLite.
- Native-only pure-Rust KV, no encryption needed → redb.
- You need multi-writer cross-process → not us.
- You're on a microcontroller → not us.
- You need a battle-tested store _today_ → SQLite. Come back to pagedb in a year.

---

## Status

Pre-1.0. The format is stabilizing toward a freeze; expect format-version bumps until that lands. The on-disk format is versioned and cipher-agile by design, so future migration paths exist — but until 1.0, treat data as throwaway.

## License

Dual-licensed under [MIT](LICENSE-MIT) **OR** [Apache-2.0](LICENSE-APACHE), at your option.
