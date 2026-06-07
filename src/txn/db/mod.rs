//! Top-level `Db<V>` façade. Owns the Pager, header state, writer slot, and
//! reader registration table, split by concern across sibling submodules.

mod catalog;
mod core;
mod gc;
mod misc;
mod open;
mod reader;
mod rekey;
mod segment;
#[cfg(not(target_arch = "wasm32"))]
mod snapshot;
mod util;

pub use core::Db;
pub(crate) use core::{CommitHistoryMeta, PendingTombstone, ReaderSnapshot, WriterState};
