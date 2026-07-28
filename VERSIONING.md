# Versioning and the Data Promise

pagedb versions two things separately.

- **The API** follows [SemVer](https://semver.org/). Pre-1.0, a minor bump may break compilation.
- **The on-disk format** has its own version and its own guarantees, set out below. They are in force from `0.1.0` and do not wait for 1.0.

## The data promise

**Your data survives every patch release.** The on-disk format never changes within a minor line. Every `0.1.x` reads and writes exactly what `0.1.0` did.

**The format changes only in a minor bump, and never silently.** If `0.2.0` changes the format, it ships with a migration tool that converts a `0.1.x` store, and the release notes say so.

**A store this build cannot read is refused, never reinterpreted.** pagedb reads exactly one format version. Anything else fails at open with `PagedbError::FormatVersionUnsupported { stored, supported }`, decided from the cleartext version before any key is derived, with the store untouched.

**A refused open is not a damaged store.** A wrong key reports `KeyMismatch`, a wrong page size `PageSizeMismatch`, a wrong realm `RealmMismatch`, and an old format `FormatVersionUnsupported`. Each says the store was not modified, because the reasonable reaction to "your database is corrupt" destroys data that a correct parameter — or a migration — would have opened.

## Migration

A format change ships a migration tool rather than in-library compatibility. Two consequences matter to you:

- **The library contains exactly one key schedule.** Reading older layouts in place would mean carrying every retired key derivation in the binary forever; keeping conversion in a separate step keeps that code out of your process.
- **A migration is verifiable.** The tool writes a new directory, runs a deep `fsck` over the result, and compares the full key space against the source before anything is swapped. Your original store is not modified until that succeeds.

Migration is always explicit. pagedb will not convert a store as a side effect of opening it.

## Path to 1.0

1.0 is gated on evidence rather than a date, and the criteria are reviewed quarterly. It ships when all of the following hold:

1. The format has not changed across two consecutive minor releases.
2. A production consumer is running on it — a real workload, at real scale, with real recovery events.
3. A second independent security review of the key hierarchy, the page envelope, and the structural formats has been completed.
4. A cumulative fuzzing bar has been met against the page, header, footer, catalog, and journal decoders.
5. A stated period has passed with no data-loss report from real deployments.

## After 1.0

The format version becomes permanent. Any store written by a `1.x` release stays openable indefinitely, and migration from any released version remains possible, always explicit, never silent.

This constrains the bytes on disk, not the release cadence: bug fixes, performance work, and new APIs continue under normal SemVer.

## Current state

|                        |                                                            |
| ---------------------- | ---------------------------------------------------------- |
| Released version       | none yet — `0.1.0` is the first                            |
| On-disk format version | 1 (`main.db` header, segment header, segment footer)       |
| Format frozen for      | the `0.1.x` line                                           |
| Migration tool         | not needed yet; ships with the first format-changing minor |

Stores written by a `0.1.0-beta` pre-release are not readable by `0.1.0`. The format moved during the pre-release series; the guarantees above begin at `0.1.0`.
