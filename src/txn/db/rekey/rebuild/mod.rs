//! Rebuild of `main.db` into a scratch file under the target key.

mod build;
mod reseal;
mod seal;
mod swap;

pub(super) use build::stage_needs_rebuild;
