//! The `pages.delta` stream of an incremental snapshot: validating its framing
//! and page ids, then streaming its records into a staged `main.db` image.
//!
//! The stream is read twice and never held: once to decide whether it is
//! admissible at all, and once to copy each record's page into the staged image
//! at its absolute offset. A delta can name every page of a large database, so
//! the only thing that scales with its size is the set of page ids the apply
//! must cross-check against the target's reachable set — never the page bytes.

use std::collections::BTreeSet;
use std::path::Path;

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::Result;
use crate::errors::PagedbError;
use crate::pager::page_space::is_reserved;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile, write_all_at};

/// What one validated `pages.delta` stream will contribute.
pub(crate) struct DeltaPlan {
    /// Page ids supplied by this exact delta stream, in ascending order.
    pub page_ids: BTreeSet<u64>,
    /// Number of page records in the stream.
    pub record_count: u64,
    /// Bytes per record: the 8-byte big-endian page id plus one page.
    record_size: u64,
}

/// Validate the framing and every page id of `src_path/pages.delta` without
/// writing anything.
///
/// `base_live_page_ids` is the base commit's *reader-visible* page set — the
/// pages both sides of the protocol can name. A delta is defined as
/// target-reachable minus base-reader-visible, so a record naming one of those
/// pages cannot come from a well-formed export; it is refused by identity, up
/// front, before any image is built.
///
/// A collision with the follower's own free-list chain or commit-history pages
/// is deliberately *not* refused here. Those pages are invisible to the
/// producer, which can neither predict nor avoid them, and the apply relocates
/// both structures out of the incoming page space rather than declaring an
/// otherwise-healthy delta inapplicable.
pub(crate) async fn plan_delta_stream(
    src_path: &Path,
    page_size: usize,
    base_live_page_ids: &BTreeSet<u64>,
    target_next_page_id: u64,
) -> Result<DeltaPlan> {
    let page_size_u64 = u64::try_from(page_size)
        .map_err(|_| PagedbError::snapshot_artifact_invalid("pages.delta.page_size"))?;
    let record_size = 8u64
        .checked_add(page_size_u64)
        .ok_or_else(|| PagedbError::snapshot_artifact_invalid("pages.delta.record_size"))?;

    let mut delta = match fs::File::open(src_path.join("pages.delta")).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DeltaPlan {
                page_ids: BTreeSet::new(),
                record_count: 0,
                record_size,
            });
        }
        Err(error) => return Err(PagedbError::Io(error)),
    };

    let delta_len = delta.metadata().await.map_err(PagedbError::Io)?.len();
    if delta_len % record_size != 0 {
        return Err(PagedbError::snapshot_artifact_invalid("pages.delta.length"));
    }

    let record_count = delta_len / record_size;
    let mut page_ids = BTreeSet::new();
    let mut id_buf = [0u8; 8];
    let page_skip = i64::try_from(page_size)
        .map_err(|_| PagedbError::snapshot_artifact_invalid("pages.delta.page_size"))?;
    for _ in 0..record_count {
        delta
            .read_exact(&mut id_buf)
            .await
            .map_err(PagedbError::Io)?;
        let page_id = u64::from_be_bytes(id_buf);
        // Reserved pages are the A/B headers and the apply-journal slots. A
        // delta record naming one would overwrite the very state that makes the
        // apply recoverable, so it is rejected by identity rather than by
        // happening to fall under some allocation bound.
        if is_reserved(page_id) || page_id >= target_next_page_id {
            return Err(PagedbError::snapshot_artifact_invalid(
                "pages.delta.page_id",
            ));
        }
        if base_live_page_ids.contains(&page_id) {
            return Err(PagedbError::snapshot_base_page_reused(page_id));
        }
        if !page_ids.insert(page_id) {
            return Err(PagedbError::snapshot_artifact_invalid(
                "pages.delta.duplicate_page_id",
            ));
        }
        delta
            .seek(std::io::SeekFrom::Current(page_skip))
            .await
            .map_err(PagedbError::Io)?;
    }

    Ok(DeltaPlan {
        page_ids,
        record_count,
        record_size,
    })
}

/// Stream every record of an already-validated delta into the staged image at
/// `image_path`, one page at a time.
///
/// The records are AEAD-sealed pages the producer wrote under the same key,
/// realm, and page id they will occupy here, so they are copied verbatim rather
/// than resealed: opening and re-sealing them would consume a nonce per page,
/// change bytes the manifest already authenticates, and buy nothing — the apply
/// authenticates every one of them by walking the target's roots through the
/// staged image before the swap.
pub(crate) async fn write_delta_into_image<V: Vfs>(
    vfs: &V,
    image_path: &str,
    src_path: &Path,
    page_size: usize,
    plan: &DeltaPlan,
) -> Result<u64> {
    if plan.record_count == 0 {
        return Ok(0);
    }
    let page_size_u64 = u64::try_from(page_size)
        .map_err(|_| PagedbError::snapshot_artifact_invalid("pages.delta.page_size"))?;
    let mut delta = fs::File::open(src_path.join("pages.delta"))
        .await
        .map_err(PagedbError::Io)?;
    let expected_len = plan
        .record_count
        .checked_mul(plan.record_size)
        .ok_or_else(|| PagedbError::snapshot_artifact_invalid("pages.delta.length"))?;
    // The stream is re-opened between the plan and this pass, so its framing is
    // re-established rather than assumed: a concurrent edit must not turn a
    // validated plan into a partial write at an unvalidated offset.
    if delta.metadata().await.map_err(PagedbError::Io)?.len() != expected_len {
        return Err(PagedbError::snapshot_artifact_invalid("pages.delta.length"));
    }

    let mut image = vfs.open(image_path, OpenMode::CreateOrOpen).await?;
    let mut id_buf = [0u8; 8];
    let mut page_buf = vec![0u8; page_size];
    let mut written = 0u64;
    for _ in 0..plan.record_count {
        delta
            .read_exact(&mut id_buf)
            .await
            .map_err(PagedbError::Io)?;
        let page_id = u64::from_be_bytes(id_buf);
        delta
            .read_exact(&mut page_buf)
            .await
            .map_err(PagedbError::Io)?;
        if !plan.page_ids.contains(&page_id) {
            return Err(PagedbError::snapshot_artifact_invalid(
                "pages.delta.page_id",
            ));
        }
        let offset = page_id
            .checked_mul(page_size_u64)
            .ok_or_else(|| PagedbError::snapshot_artifact_invalid("pages.delta.page_offset"))?;
        write_all_at(&mut image, offset, &page_buf).await?;
        written = written.saturating_add(1);
    }
    image.sync().await?;
    Ok(written)
}
