//! Online compaction: main.db defragmentation and segment repacking.
//!
//! Free-page reclamation itself is handled at runtime by the durable free-list
//! ([`crate::pager::freelist`]); compaction's job is the dense repack + file
//! truncation and segment garbage collection.
//!
//! Entry points: [`compact_now`] (full one-shot) and [`compact_step`]
//! (one atomic pass with a progress report) on a [`crate::Db`] handle.

#[cfg(test)]
mod cancel_tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod catalog_move_tests;
mod full;
mod helpers;
mod repack;
mod step;
mod types;

pub use full::compact_now;
pub use step::compact_step;
pub use types::{CompactBudget, CompactProgress, CompactStats};
