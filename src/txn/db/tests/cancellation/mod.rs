//! Dropping a write-side future at a fixed await, then checking the handle and
//! the reopened store.

#[cfg(not(target_arch = "wasm32"))]
mod apply;
mod commit;
mod compact;
mod gating;
mod header_errors;
mod maintenance;
mod mutation;
mod rekey;
mod support;
