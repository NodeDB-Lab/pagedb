//! Top-level `Db<V>` façade. Owns the Pager, header state, writer slot, and
//! reader registration table, split by concern across sibling submodules.

mod apply_journal;
mod catalog;
mod core;
mod gc;
// Serves the native-only incremental-snapshot apply path, like `reclaim` below;
// gate it the same way.
#[cfg(not(target_arch = "wasm32"))]
mod history_carry;
// Serves the native-only incremental-snapshot apply path: its sole caller is
// `snapshot` (wasm-gated below) and it imports `SnapshotManifest` from the
// wasm-gated `crate::snapshot::export`. Gate it the same way so the wasm build
// does not pull an import that is configured out.
#[cfg(not(target_arch = "wasm32"))]
mod manifest_validation;
mod misc;
mod open;
mod pending;
mod reader;
// Serves the native-only incremental-snapshot apply path, like
// `manifest_validation` above; gate it the same way.
#[cfg(not(target_arch = "wasm32"))]
mod reclaim;
pub(crate) mod rekey;
mod segment;
#[cfg(not(target_arch = "wasm32"))]
mod snapshot;
#[cfg(test)]
mod tests;
mod util;

pub use core::Db;
pub(crate) use core::{CommitHistoryMeta, WriterState, encode_free_list_root};
pub(crate) use pending::PendingWriterState;
