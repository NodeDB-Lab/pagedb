//! Online compaction: main.db defragmentation and segment repacking.
//!
//! Free-page reclamation itself is handled at runtime by the durable free-list
//! ([`crate::pager::freelist`]); compaction's job is the dense repack + file
//! truncation and segment garbage collection.
//!
//! Entry points: [`compact_now`] (full one-shot) and [`compact_step`]
//! (incremental, budget-bounded) on a [`crate::Db`] handle.

mod full;
mod helpers;
mod step;
mod types;

pub use full::compact_now;
pub use step::compact_step;
pub use types::{CompactBudget, CompactProgress, CompactStats};
