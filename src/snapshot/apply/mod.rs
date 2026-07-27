//! Applying an incremental snapshot to a Follower: the delta stream, the staged
//! `main.db` image it is written into, and the segment staging area.

#![cfg(not(target_arch = "wasm32"))]

pub(crate) mod delta;
pub(crate) mod image;
pub(crate) mod segments;

pub(crate) use delta::{plan_delta_stream, write_delta_into_image};
pub(crate) use image::{clone_base_image, discard_staged_image, staged_image_path};
pub(crate) use segments::{stage_snapshot_segments, validate_snapshot_segment_count};
