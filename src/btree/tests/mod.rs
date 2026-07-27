//! B+ tree tests that exercise the physical node format and the walks over it.
//! They live here rather than in `tests/` because the node/leaf/internal codecs
//! are crate-internal — an embedder never sees a slot array or a page id.
#![allow(clippy::pedantic)]

mod basic;
mod generated_nodes;
mod generated_overflow_chains;
mod generated_structural_walks;
mod overflow_walk_offset;
mod tree_ops;
