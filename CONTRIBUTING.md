# Contributing to pagedb

Thanks for your interest. `pagedb` is a single library crate with one job — be the encrypted, portable substrate two very different storage surfaces sit on — so most contributions are small and land in one layer.

---

## Where to Start

- **[GitHub Issues](https://github.com/nodedb-lab/pagedb/issues)** — bug reports and well-scoped feature requests.

A bug report with a `MemVfs`-based reproducing test is worth more than a long description: it removes the filesystem, the platform, and timing from the question in one move. For anything that changes the on-disk format, the public API, or a durability ordering, open an issue before writing the PR.

---

## What This Crate Is

`pagedb` holds data an embedder believes is safe, and has to still be able to read it years later on a different operating system. Three consequences shape almost every review comment:

- **Every persistent byte is authenticated, and nothing bypasses the Pager.** There is no mode that writes unauthenticated bytes and no write path that skips the AEAD layer. A change that adds one is not a performance tradeoff to weigh; it is out of scope.
- **A crash must never be able to corrupt committed state.** The B+ tree commits by copy-on-write behind alternating A/B headers; a segment commits by its seal record or not at all. Any new durability step has to say where its crash point is and what a reopen sees on each side of it.
- **The format is the contract.** A directory written on any supported target opens byte-identically on every other. Endianness, padding, reserved bytes, and enum values are all persisted, so a "harmless" struct change can be a format break.

The crate is `async` throughout and has no C dependencies, on purpose: it targets browsers over OPFS with the same code that runs on Linux. Adding a C dependency, or a blocking call in an async path, is not a change we can take.

---

## Architecture Primer

```
Layer 3a: B+ Tree            Layer 3b: Segment File API
sorted bytes→bytes,          append-mostly encrypted files,
ACID, range scans            engine-owned format
─────────────────────────────────────────────────────────
Layer 2: Pager   (cache, AEAD, prefetch, vectored I/O)
─────────────────────────────────────────────────────────
Layer 1: Vfs     (File trait, direct I/O, advisory locks)
─────────────────────────────────────────────────────────
io_uring │ IOCP │ dispatch_io │ OPFS worker │ thread pool
```

Both surfaces share one Pager and one VFS. That sharing is the whole point — an engine that wants its own block format still inherits encryption, durability, and portability — so a change that gives one surface a private path around the Pager defeats the design regardless of how local it looks.

Source layout mirrors the layers: `vfs/`, `pager/`, `crypto/`, `btree/`, `segment/`, `catalog/`, `txn/`, `realm/`, `snapshot/`, `recovery/`, `compaction/`.

---

## Invariants

These are enforced in review. They are properties of the format and the failure model, not preferences.

- **No `mmap` of encrypted bytes.** `mmap_view` maps already-decrypted scratch, native only, under an explicit byte budget.
- **Every persistent page is authenticated.** No mode omits integrity.
- **Nonce reuse is impossible under one key**, by construction rather than by probability. The nonce is `file_identity[0..6] ‖ counter48`, so keys are scoped per `(realm, file, master-key epoch, cipher)`. A key shared across two files would put two counters in one nonce space; that is the bug the scoping exists to prevent.
- **`RealmId` is bound into the AAD of every persistent page in every cipher mode**, and recorded in the `main.db` header so a mismatched open is refused rather than discovered later as an unreadable page.
- **Segment files are identity-keyed.** The path is `seg/<hex(segment_id)>`; the embedder-visible name lives only in the catalog. This is what makes names collision-free, replaceable without a stall, and portable across filesystems.
- **Segment lifecycle is transactional** — `link_segment` / `replace_segment` / `unlink_segment`. There is no unmediated drop.
- **Torn writes never corrupt.** A/B headers for `main.db`, the seal record for segments.
- **Bounded memory.** Budgets are explicit `OpenOptions` fields, not implicit growth.
- **Cipher-agile.** Every encrypted byte carries its `cipher_id`, and reads dispatch on the recorded byte rather than the configured one.

---

## What We Welcome

- Bug fixes with a reproducing test.
- Crash-safety coverage — new interruption points at real seams, especially in recovery, compaction, rekey, and snapshot apply.
- Adversarial decoder coverage: `proptest` cases for formats that can currently be handed bytes they do not reject.
- Platform fixes. The `io_uring`, IOCP, `dispatch_io`, and OPFS backends are where portability and memory-safety bugs live.
- Performance work with `fluxbench` evidence, provided it does not weaken an invariant above.
- Documentation fixes.

## What to Discuss First

- **On-disk format changes.** Anything touching the page envelope, AAD layout, structural headers, the segment footer, catalog rows, the journal, or the snapshot manifest. Format versions move in lockstep across `main.db` and segments, a change may only land in a minor bump, and it must ship with a migrator — see [VERSIONING.md](VERSIONING.md). Open an issue before writing it; the migration is part of the change, not a follow-up.
- **Key hierarchy or nonce discipline changes.** These are the crate's load-bearing security properties.
- **Public API changes**, including new `Vfs` / `VfsFile` trait methods without defaults — embedders implement those.
- **Durability ordering changes** — fsync placement, `sync_dir` calls, the header swap point.
- **New dependencies.** The default build is deliberately small and C-free; each optional feature carries its own tree and stays optional for that reason.

## What We Don't Accept

- Cosmetic-only changes with no functional effect.
- AI-generated code submitted without the author having reviewed and understood it.
- `#[ignore]` or a narrowed assertion used to make a real coverage gap green. A real test is left red; a speculative one is deleted.
- A new `unsafe` block outside `vfs/` and the `mmap_view` decrypted-scratch path, or any `unsafe` block without a `// SAFETY:` comment stating what makes it sound.
- `.unwrap()` or `.expect()` in library code, and `Result<T, String>` anywhere. Errors are typed and land in `PagedbError` via `From`; construct them through the constructors (`PagedbError::corruption(...)`, `PagedbError::quota(...)`), not as raw struct literals.
- Build-order markers in source, test names, or comments — phase, wave, milestone, or step labels, or references to an internal planning document a reader cannot open. Code is organized by what it does, not by the order it was built. Comments explain _behaviour_; test names state _what they assert_.

---

## Development Setup

**Requirements:**

- Rust 1.85 or later (the MSRV in `Cargo.toml`; edition 2024 needs it).
- `cargo-nextest` for the test suite.
- Linux 5.1+ gets the `io_uring` backend; older kernels and other platforms fall back automatically, and the suite passes on all of them.

```bash
cargo install cargo-nextest --locked

git clone https://github.com/nodedb-lab/pagedb.git
cd pagedb
cargo nextest run --all-features
```

**Why nextest, not `cargo test`?** `.config/nextest.toml` serializes the crash-recovery tests, several of which re-exec the test binary as a child process or contend for one advisory lock. `cargo test` ignores that config and produces false negatives.

`cargo test --doc` still runs the doctests, which nextest does not.

---

## Code Standards

Everything below runs in CI and blocks merge. Run them **one at a time, not chained** — concurrent `cargo` invocations fight over `target/`:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo deny check
cargo doc --no-deps --all-features   # RUSTDOCFLAGS="-D warnings"
```

CI additionally checks the feature matrix, the MSRV, the cross-platform matrix (Linux, macOS, Windows), the wasm targets, and `cargo package`.

Key rules:

- No `.unwrap()` in library code; tests may unwrap.
- `mod.rs` contains only `pub mod` and `pub use` — no types, no logic, no impls.
- **Directory-first modules.** A module with any chance of growing starts as `foo/mod.rs` with its concerns in sibling files. Splitting after the fact churns imports, history, and review diffs.
- Prefer many small, focused files over few large ones. 500 lines is a smell, not a limit — by then the split should already have happened structurally.
- No `std::sync::Mutex` held across `.await`; use `tokio::sync` or restructure.
- No unbounded channels in hot paths.
- All key material is `zeroize`d on drop, and key types never derive `Debug` or `Clone` without it.

---

## Testing

**Unit tests** go in the same file under `#[cfg(test)] mod tests` and may test private functions. **Integration tests** go in `tests/`, grouped by concern, and use the public API only; shared helpers live in `tests/common/mod.rs` (not `tests/common.rs`).

**Prefer `MemVfs` for anything not testing the filesystem.** It makes byte-level damage trivial to inject and removes platform timing from the result. The VFS backends have their own suites where the real filesystem is the subject.

**Crash tests interrupt the real code at its real seam.** Arming a fault point inside the commit, anchor-refresh, or rekey path and asserting what a reopen sees is the shape that catches ordering bugs. Zeroing bytes afterwards and calling it a torn write tests the decoder, not the protocol — both are useful, but do not confuse one for the other.

**A test that damages a store must assert what survives, not only what fails.** "The wrong key is refused" is half the property; "and the right key still opens it, with its data" is the half that catches a fix which quietly destroys the store on the way to a clean error.

**Format changes need a round-trip test per page size** (4 KiB through 64 KiB) and a rejection test for the superseded version. A decoder that silently accepts an older layout is a data-corruption bug, not a compatibility feature.

When fixing a bug, add the test first and confirm it fails for the reason you think it does.

---

## Benchmarks

Benchmarks use **`fluxbench`**, not criterion, and live in `benches/`:

```bash
cargo bench --bench btree
cargo bench --bench segment
```

Keep the `Db` alive across iterations, time only the operation, and compare like with like — pagedb's B+ tree against redb, pagedb's segments against raw `tokio::fs` plus AEAD. The cross-engine suite is a separate non-default workspace package so an ordinary test run never resolves RocksDB, redb, or SQLite.

Performance claims in a PR need before/after numbers from the same machine in the same run.

---

## Commits and Pull Requests

**Commit format** — [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(crypto)!: scope data keys by file identity
fix(pager): keep a re-dirtied page dirty across a flush
perf(btree): avoid a body copy on the warm read path
test(crash): interrupt an anchor refresh after its header write
docs(readme): state what the security model does not cover
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `ci`, `chore`. Mark a format or API break with `!`.

**One logical change per commit.** If a PR touches several concerns, split it so a reviewer can follow the intent.

**Update `CHANGELOG.md`** under `## [Unreleased]` for anything a user would notice — a fix, a new capability, a behaviour change, and always for a format change. The release workflow refuses to cut a tag whose version has no changelog section, and publishes that section as the release notes, so this is what your change will be announced as.

**Draft PRs are welcome** — open one early for directional feedback before investing in a full implementation.

**PR description should cover:** what the change does and why, how to test it, any tradeoff you made, and — for anything touching the format or a durability ordering — what an existing store does on upgrade.

**Review timeline:** this is a small project; PRs may not be reviewed immediately.

---

## Releasing

Maintainers only, and deliberately manual:

1. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z]` with the date.
2. Push a `vX.Y.Z` tag. `Release Prepare` validates the tag against `Cargo.toml`, requires a non-empty `## [X.Y.Z]` changelog section, runs the full suite, and builds the `pagedb-fsck` binaries.
3. Dispatch `Release` with that tag and the prepare run ID. It publishes to crates.io and cuts the GitHub release from the changelog section.

Prerelease tags (`vX.Y.Z-beta.N`) are validated against the base version's changelog section, so a beta rehearses the notes the final release will carry. `Cargo.toml` only has to carry the right *base* version — `scripts/ci/stamp_version.sh` writes the exact version from the tag.

---

## Security

Do not report security vulnerabilities in public issues. Use [GitHub Security Advisories](https://github.com/nodedb-lab/pagedb/security/advisories/new). See [SECURITY.md](SECURITY.md) for what qualifies and how we respond — in particular, rollback of the store files by an attacker with write access is a stated design boundary rather than a defect, and the [security model](README.md#security-model) says why.

---

## License

`pagedb` is dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option. Contributions are accepted under the same terms, as described in the Apache-2.0 license. No CLA is required.
