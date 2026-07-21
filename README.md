# pagedb

**An encrypted, portable, embedded page store for Rust.** Pure Rust, async-native, no C dependencies, no `mmap` of encrypted bytes. Runs on Linux, macOS, Windows, iOS, Android, browsers (WASM/OPFS), and WASI — with format-bit-identity across every target.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)]() [![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-orange.svg)]()

---

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

## Benchmarks

Measured on native NVMe, AES-NI host, single thread, via `fluxbench`. Reproduce the
PageDB-owned benches and the isolated cross-engine suite with:

```bash
cargo bench --bench segment
cargo bench -p pagedb-engine-comparison --bench btree
cargo bench -p pagedb-engine-comparison --bench comparison
```

The comparison suite is a non-default workspace package under
[`benchmarks/engine-comparison`](./benchmarks/engine-comparison). Normal
`cargo test` and `cargo nextest` runs for the `pagedb` package therefore do not
resolve or compile RocksDB, redb, or SQLite.

### vs. redb (B+ tree, in-process)

| Workload                       |      pagedb |    redb | Speedup vs redb |
| ------------------------------ | ----------: | ------: | --------------: |
| Point get (per-txn)            |  **204 ns** |  416 ns |       **2.04×** |
| Batched insert (1000 keys/txn) |  **711 µs** | 1.76 ms |       **2.47×** |
| Per-txn insert (in-memory)     | **20.3 µs** |  975 µs |         **48×** |
| Per-txn insert (file, AEAD on) |    147.7 µs |  975 µs |        **6.6×** |

AEAD overhead on reads is **~1.00×** — encryption is effectively free on hot reads thanks to in-cache plaintext.

### vs. redb / RocksDB / SQLite (full comparison suite)

| Workload                       |     pagedb |       redb |     RocksDB |     SQLite |
| ------------------------------ | ---------: | ---------: | ----------: | ---------: |
| **Random point read**          | **383 ns** |     1.3 µs |      2.0 µs |    13.2 µs |
| **Range scan**                 | **529 ns** |     1.9 µs |      4.6 µs |    32.2 µs |
| Individual write (fsync-bound) |    71.2 µs |    23.7 µs |  **7.4 µs** |    58.4 µs |
| Batch write                    |    9.31 ms |    3.39 ms | **1.97 ms** |    5.00 ms |
| Bulk load                      |     626 ms | **124 ms** |      265 ms |     169 ms |
| Sorted bulk load               |     349 ms |     113 ms |      146 ms | **102 ms** |

**pagedb wins reads decisively** (3.3× redb on point reads, 3.7× on range scans) and **trails on writes**. The write gap is the deliberate price of AEAD on every page, CoW shadow paging with A/B headers, async I/O, and per-realm AAD binding — none of which redb or RocksDB carry. Write-throughput optimization is on the roadmap (group-commit tuning, write-coalescing, vectored fsync), but reads are where the architecture pays off today.

### Segment writer (append + seal)

| Path                            |       mean | Notes                               |
| ------------------------------- | ---------: | ----------------------------------- |
| Raw AES-GCM only (memory)       |     300 µs | baseline: encryption cost alone     |
| **pagedb `append_seal`**        | **525 µs** | full path: write, seal, fsync, link |
| Raw `tokio::fs` write + AES-GCM |    1.50 ms | what you'd write yourself, badly    |

pagedb's segment writer adds **~1.74× over raw AEAD** but is **2.9× faster than a hand-rolled `fs::write` + AES-GCM** baseline — because pagedb batches, vectorizes, and uses the platform's best async primitive.

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

redb skips all of this. The trade is deliberate, not a bug. Read-heavy workloads come out ahead; write-heavy workloads pay the safety/portability tax until further write-path tuning lands.

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
