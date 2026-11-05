//! Dropping a write-side future at a fixed await, then checking the handle and
//! the reopened store.

#[cfg(not(target_arch = "wasm32"))]
mod apply;
mod commit;
mod compact;
mod gating;
mod maintenance;
mod rekey;
mod support;
