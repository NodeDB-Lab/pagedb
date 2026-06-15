//! Single-shot compaction exposed under the [`compact_step`] entry point.
//!
//! Compaction shrinks main.db by rebuilding it atomically (scratch file +
//! rename — see [`super::repack`]). A full rewrite cannot be safely chunked
//! across writer-lock releases: commits made by other writers between chunks
//! would be silently dropped by the final rename. So `compact_step` performs the
//! whole atomic compaction in a single call and reports completion.
//!
//! This is not a limitation of reclamation in general — sustained-write growth
//! is bounded continuously by the durable free-list (every commit reuses freed
//! pages), so returning space to the OS is a maintenance operation rather than a
//! hot path.

use crate::Result;
use crate::txn::db::Db;
use crate::vfs::Vfs;

use super::types::{CompactBudget, CompactProgress};

/// Run a full compaction and report what it reclaimed.
///
/// `budget` is accepted for interface stability with the incremental-style API
/// but does not chunk the work (see the module docs for why a full rewrite can't
/// be safely chunked). Compaction runs atomically to completion and always
/// returns `more_work = false`; to reclaim periodically, call this again later.
///
/// Returns `PagedbError::Unsupported` if the handle is not in `Standalone` mode.
pub async fn compact_step<V: Vfs + Clone>(
    db: &Db<V>,
    budget: CompactBudget,
) -> Result<CompactProgress> {
    let _ = budget;
    let stats = super::full::compact_now(db).await?;
    Ok(CompactProgress {
        pages_relocated: stats.main_db_pages_reclaimed,
        bytes_freed: stats.bytes_truncated,
        more_work: false,
        watermark: None,
    })
}
