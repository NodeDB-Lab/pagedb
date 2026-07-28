# Security Policy

`pagedb` is **pre-1.0**. Interfaces, defaults, and the on-disk format may change between releases. Security reports are investigated regardless — this policy explains what qualifies, how to report it, and how we respond.

A storage engine has a particular security shape: it holds data an embedder believes is safe, it must still be readable years after it was written, and every guarantee it offers is cryptographic rather than procedural. A defect here does not merely misbehave — it loses or exposes data that nothing else in the stack was watching.

## Supported Versions

While `pagedb` is pre-1.0, fixes are issued **only against the latest released version**. There are no backports to earlier `0.x` releases.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Always run the latest release; it carries every prior fix. A security fix may require an on-disk format change; per [VERSIONING.md](VERSIONING.md) such a change lands only in a minor bump and ships with a migration tool, and is called out in [CHANGELOG.md](CHANGELOG.md).

## What Qualifies as a Security Vulnerability

In scope:

- **Recovering plaintext or key material without the KEK.** Any path by which page contents, a derived key, or the master key can be read from the store bytes, from memory pagedb chose to leave behind, or from an error message.
- **Forging or substituting authenticated bytes.** A page, segment, structural header, or footer that verifies while not being what the store wrote at that position — including moving a genuine page to another page id, realm, segment, or page kind.
- **Key-separation failures.** Nonce reuse under one key, one key serving two files or two realms, or a derivation that lets a caller influence another scope's key. The nonce is `file_identity[0..6] ‖ counter48`, so a key shared across files is a nonce-reuse bug even if no collision is demonstrated.
- **Crossing a `RealmId` boundary.** Reading or writing pages belonging to a realm the handle was not opened with.
- **Committed data lost or silently altered** by a crash, an open-flow recovery, a compaction, an online rekey, a snapshot export, or an incremental apply. A commit that returned `Ok` and is not there after reopen is in scope, as is a reopen that serves a page from a different commit than the header names.
- **Memory-unsafety in any `unsafe` block** — the VFS backends (`io_uring`, IOCP, `dispatch_io`, OPFS) and the `mmap_view` decrypted-scratch path are the only places `unsafe` is permitted, and are where such bugs will be.
- **A panic, abort, or unbounded allocation reachable from untrusted store bytes.** Refusing to open a damaged store is the correct behaviour; panicking inside a decoder is not.

Generally **not** vulnerabilities — still worth reporting as ordinary bugs, in public issues:

- **Rollback and replay.** A page's tag binds where the page belongs, not when it was written. An attacker who can write to the store files can substitute an older genuine ciphertext, or restore an older copy of the whole directory, and it will authenticate. This is a stated design boundary — see [Security model](README.md#security-model) — not a defect. Freshness, if you need it, belongs above pagedb.
- **An attacker who can already read the host process's memory.** Keys, plaintext pages, and the buffer pool live there. pagedb zeroizes what it owns on drop; it cannot defend a live process from a debugger, a core dump, or swap.
- **No confidentiality in `PlaintextMac` mode.** That mode is integrity-only by definition, opt-in at open, and recorded in the header so an auditor can tell which mode a deployed store uses.
- **Metadata visible from the store's shape** — file sizes, page counts, segment counts, commit frequency, access patterns. Keys and values are encrypted; the shape of the workload is not.
- **Resource exhaustion from a legitimate caller** writing more than the configured budgets allow. Configure `OpenOptions` (`scratch_bytes`, `buffer_pool_pages`, `segment_cache_pages`, `mmap_view_scratch_bytes`, `reader_stall_threshold_pages`). A panic or unbounded allocation from _malformed store bytes_, by contrast, is in scope.
- **KEK management.** Deriving, storing, rotating, and destroying the 32-byte KEK is the embedder's job. pagedb takes it and never persists it.
- **Vulnerabilities in third-party dependencies already tracked by their own advisory.** Please still tell us so we can upgrade.
- **Issues in development tooling** (benchmarks, tests, CI scripts) that do not affect the published crate or the `pagedb-fsck` binary.

If you are unsure, err on the side of reporting privately.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Report privately through GitHub Security Advisories:

> [Report a vulnerability](https://github.com/nodedb-lab/pagedb/security/advisories/new)

Or use the repository's **Security** tab → **Advisories** → **Report a vulnerability**. This opens a private channel between you and the maintainers; nothing is public until an advisory is published.

Please include:

- **Overview** — the issue and its security impact.
- **Affected version** — the `pagedb` version or commit, and which features were enabled (`diagnostics`, `compression`, `opfs`).
- **Environment** — OS, architecture, and VFS backend (`io_uring`, IOCP, `dispatch_io`, thread-pool, OPFS, WASI). Much of the `unsafe` surface is platform-specific.
- **Reproduction** — a test, a sequence of API calls, or a store directory that exhibits it. A `MemVfs`-based reproducer is ideal; it removes the filesystem from the question.
- **Evidence** — proof-of-concept code, a `pagedb-fsck --deep` report, log excerpts, a stack trace, or a patch if you have one.
- Whether the issue is already public or under coordinated disclosure elsewhere.

If your report includes a store directory, please build it from synthetic data. Do not send us a store containing anyone's real data.

## Our Response

When you report an issue we will:

1. **Acknowledge** receipt within **3 business days**.
2. Give an **initial assessment** — confirmed, needs more information, or not a vulnerability, with severity and scope — within **10 business days**.
3. Keep you **updated at least every 14 days** while a fix is in progress.
4. Prepare the fix, cut a release, and **publish a GitHub Security Advisory once the fixed release is on crates.io** — unless the issue is already public.

We coordinate disclosure: reporter and maintainers agree an embargo, typically up to 90 days and shorter for actively-exploited issues, and we ask that the issue not be disclosed publicly until a fixed release is out.

Where a fix cannot be applied to existing stores in place — a format change, or a key derivation change — the advisory states what an operator has to do to migrate, not only what the code now does.

## CVEs

Advisories are published through GitHub Security Advisories, which acts as the CVE Numbering Authority; we request a CVE when an issue warrants one. Pre-1.0, many advisories will carry a GHSA identifier only. Please **do not register a CVE independently** — coordinate through the advisory so the record stays accurate.

Published advisories are listed on the repository's [Security Advisories](https://github.com/nodedb-lab/pagedb/security/advisories) page.

There is no bug bounty.

## Credit and Safe Harbor

Reporters are credited in the advisory and release notes by default. Say so in your report if you would rather stay anonymous or use a specific handle.

Security research conducted in good faith under this policy is authorized, and we will not pursue legal action for it. In return we ask that you:

- Give us reasonable time to fix the issue before public disclosure.
- Use only the access needed to demonstrate the issue, and do not exfiltrate data that is not yours.
- Do not test against infrastructure you do not own.

## Scope

In scope: the `pagedb` crate published on crates.io and this repository's library sources — the key hierarchy and cipher dispatch, the page envelope and AAD binding, the A/B header and segment footer formats, the B+ tree and segment surfaces, the free-list and reclamation paths, the recovery, compaction, rekey and snapshot paths, every shipped VFS backend, and the `pagedb-fsck` binary.

Out of scope: the embedder's own KEK handling and `Vfs` implementation, third-party dependencies already covered by their own advisory, and the non-vulnerability categories above.

## Security Practices

- Dependencies are audited in CI with **`cargo deny check`** against the RustSec advisory database, plus license and source-ban policy — across every target triple the VFS matrix covers, so a vulnerable Windows-only dependency is caught on a Linux runner.
- Clippy runs with `-D warnings` across all targets and all features; the crate is `#![deny(unsafe_code)]` with per-module exceptions confined to the VFS backends and `mmap_view`.
- The suite runs under `cargo nextest`, which honours the serialization the crash-recovery tests need. Crash and torn-write cases are driven by interrupting the real code at its real seams — armed fault points inside the commit, anchor-refresh, rekey and publication paths — rather than by simulating damage afterwards.
- The decoders and the structural walks are covered by generated adversarial input (`proptest`) inside the normal test run, on every Tier-1 target, so a decoder panic is a test failure rather than a fuzzing-campaign finding.
- Format identity across targets is a release gate: a directory written on any supported target must open byte-identically on every other.

## Hardening Notes for Adopters

- **Treat a refused open as a parameter problem first.** A wrong KEK reports `PagedbError::KeyMismatch`, a wrong page size `PageSizeMismatch`, and a wrong realm `RealmMismatch` — each decided before anything is read or written, and none of them evidence of damage. Retry with the right parameter. Do not discard the directory.
- **Back up the directory as a unit.** Segment files are identity-keyed and the name-to-identity mapping lives only in the catalog inside `main.db`. Losing `main.db` while `seg/` survives is unrecoverable.
- **Zeroize your KEK.** `pagedb` takes `[u8; 32]` and immediately moves it into a zeroizing wrapper, but the array you passed is still yours to clear.
- **Give each isolation scope its own `RealmId`.** A realm is a key boundary and an AAD binding, not a label; one realm per tenant is what makes a misrouted read fail closed.
- **Set `mmap_view_scratch_bytes` only if you need it.** It defaults to zero, which refuses `mmap_view` outright. Enabling it means decrypted bytes are mapped into your address space.
- **Enable `diagnostics` deliberately.** Reports are inert until the host calls `faultbox::init`, and pagedb keeps embedder-chosen names out of them — but a report still names page ids, realms, and the store path. Treat the reports directory as data at rest.
- **Run `pagedb-fsck --deep` before trusting a store you did not write** — after a restore, after a hardware fault, or when triaging. It opens frozen read-only and never rewrites authoritative bytes.
