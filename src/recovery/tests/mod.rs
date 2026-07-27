//! Recovery tests that drive the apply-journal directly. They live here rather
//! than in `tests/` because the journal record codec and its executor are
//! crate-internal: calling them out of order bypasses `Db::open`'s recovery
//! sequencing.
#![allow(clippy::pedantic)]

mod apply_journal_crash;
mod generated_journal_records;
