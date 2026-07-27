//! Snapshot export/restore tests. They live here rather than in `tests/`
//! because the manifest codec and the delta-page applier are crate-internal.
#![allow(clippy::pedantic)]

mod basic;
mod generated_artifacts;
