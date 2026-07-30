//! Durable free-page list, stored as a chain of `PageKind::Free` pages rooted
//! at the A/B header's `free_list_root` slot — outside the catalog B+ tree.
//!
//! Keeping the free list out of the catalog is what makes free-page recycling
//! both **durable** (it survives an unclean shutdown — the chain is committed
//! atomically with the header swap) and **bounded** (maintaining it never
//! copies-on-writes the catalog tree, so it adds no per-commit catalog churn).
//!
//! Each entry is a `(commit_id, page_id)` pair: `commit_id` is the commit that
//! freed the page, used at `begin_write` to decide which pages are below the
//! reclamation floor (observable by no reader and no retained-history root) and
//! therefore safe to recycle now. The chain stores *every* free page — those
//! still pinned are simply carried forward until the floor advances past them.
//!
//! The chain is singly linked and self-describing: each page carries its own
//! `next` and entry count, no page encodes another page's offset, and the
//! header publishes only the head. A **prefix rewrite** therefore needs no
//! format change — write J fresh pages, point the last one's `next` at the
//! first retained tail page, publish the new head — and it is what keeps the
//! write hot path's resident cost independent of how many pages are free.

pub(crate) mod budget;
pub(crate) mod layout;
pub(crate) mod read;
pub(crate) mod write;

#[cfg(test)]
mod tests;

pub use budget::WINDOW_PAGES;
pub use layout::CHAIN_METADATA_CID;
pub use read::{
    ChainTail, ChainWalk, count_at_or_above_floor, count_chain, read_chain, read_chain_prefix,
};
pub use write::rewrite_chain;

// Forging a chain by hand is a test-only need: production writes go through
// `rewrite_chain`, which owns host selection and the tail splice — and reads a
// chain's summary only as part of the window walk that precedes it.
#[cfg(test)]
pub use layout::chain_capacity;
#[cfg(test)]
pub use read::read_chain_summary;
#[cfg(test)]
pub use write::write_chain;
