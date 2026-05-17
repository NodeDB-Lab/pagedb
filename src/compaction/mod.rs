//! Online compaction: persistent free-list management, main.db defragmentation,
//! and segment repacking.
//!
//! Entry points: [`compact_now`] (full one-shot) and [`compact_step`]
//! (incremental, budget-bounded) on a [`crate::Db`] handle.

pub mod freelist;
mod full;
mod helpers;
mod step;
mod types;

pub use freelist::{
    alloc_page, drain_deferred_to_freelist, free_page_deferred, persist_freelist_state,
};
pub use full::compact_now;
pub use step::compact_step;
pub use types::{CompactBudget, CompactProgress, CompactStats};
