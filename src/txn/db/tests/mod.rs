//! `Db`-level durability tests that inject VFS faults and also drive the
//! crate-internal apply-journal executor, so they cannot live in `tests/`.
#![allow(clippy::pedantic)]

mod metadata_errors;
