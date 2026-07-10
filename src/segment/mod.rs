//! Engine-owned encrypted segment files. Append-mostly, sealed atomically,
//! identity-keyed paths.

pub(crate) mod authenticated_metadata;
#[cfg(not(target_arch = "wasm32"))]
pub mod mmap;
pub mod reader;
pub mod types;
pub mod writer;

pub use reader::SegmentReader;
pub use types::{ExtentRef, GcStats, MmapView, PageId, SegmentPageKind};
pub use writer::SegmentWriter;
