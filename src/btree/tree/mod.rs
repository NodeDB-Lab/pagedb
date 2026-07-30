//! `BTree` — the `CoW` shadow-paging B+ tree.

pub(crate) mod bulk;
pub(crate) mod core;
pub(crate) mod flush;
pub(crate) mod maintenance;
pub(crate) mod navigate;
pub(crate) mod page_source;
pub(crate) mod read;
pub(crate) mod scan;
pub(crate) mod write;

pub use core::BTree;
pub use page_source::{ConsumedPages, PageSource};
