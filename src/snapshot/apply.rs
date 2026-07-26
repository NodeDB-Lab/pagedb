//! `apply_incremental`: reads a delta snapshot stream and applies it to a
//! Follower handle by writing pages directly and then swapping the A/B header.

#![cfg(not(target_arch = "wasm32"))]

use std::{collections::BTreeSet, path::Path};

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::Result;
use crate::errors::PagedbError;
use crate::pager::page_space::is_reserved;

/// Pages consumed from one `pages.delta` stream during an incremental apply.
pub struct AppliedDeltaPages {
    /// Number of page records written to `main.db`.
    pub pages_applied: u64,
    /// Page IDs supplied by this exact delta stream.
    pub page_ids: BTreeSet<u64>,
}

/// Apply an incremental snapshot directory (`src_path`) to the Follower's
/// `main.db` file at `main_db_path` (absolute filesystem path). Returns stats.
///
/// Crash-safety: pages are written first, then the header swap happens via the
/// normal `commit_header` path in `Db::apply_incremental`.
pub async fn apply_delta_pages(
    src_path: &Path,
    dst_main_db_path: &Path,
    page_size: usize,
    protected_page_ids: &BTreeSet<u64>,
    target_next_page_id: u64,
) -> Result<AppliedDeltaPages> {
    let delta_path = src_path.join("pages.delta");
    let mut delta = match fs::File::open(&delta_path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AppliedDeltaPages {
                pages_applied: 0,
                page_ids: BTreeSet::new(),
            });
        }
        Err(e) => return Err(PagedbError::Io(e)),
    };

    let page_size_u64 = u64::try_from(page_size)
        .map_err(|_| PagedbError::snapshot_artifact_invalid("pages.delta.page_size"))?;
    let record_size = 8u64
        .checked_add(page_size_u64)
        .ok_or_else(|| PagedbError::snapshot_artifact_invalid("pages.delta.record_size"))?;
    let delta_len = delta.metadata().await.map_err(PagedbError::Io)?.len();
    if delta_len % record_size != 0 {
        return Err(PagedbError::snapshot_artifact_invalid("pages.delta.length"));
    }

    // Validate every record before opening main.db for writes. A malformed
    // record late in the stream must not leave a valid prefix written into the
    // follower's future page range.
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
        // The follower keeps its own free-list chain and commit-history tree
        // across an apply, and those pages are invisible to the producer, which
        // can neither predict nor avoid them. A collision is therefore not a
        // malformed artifact — both states are internally sound, they simply
        // cannot be related by a page delta — so it reports as
        // `SnapshotBasePageReused` and the remedy is a full snapshot or a nearer
        // base. Caught here, before `main.db` is opened for writing.
        if protected_page_ids.contains(&page_id) {
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
    delta
        .seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(PagedbError::Io)?;

    let mut dst = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dst_main_db_path)
        .await
        .map_err(PagedbError::Io)?;
    let mut page_buf = vec![0u8; page_size];
    for _ in 0..record_count {
        delta
            .read_exact(&mut id_buf)
            .await
            .map_err(PagedbError::Io)?;
        let page_id = u64::from_be_bytes(id_buf);
        delta
            .read_exact(&mut page_buf)
            .await
            .map_err(PagedbError::Io)?;

        // Write page to main.db at the correct offset.
        let offset = page_id
            .checked_mul(page_size_u64)
            .ok_or_else(|| PagedbError::snapshot_artifact_invalid("pages.delta.page_offset"))?;
        dst.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(PagedbError::Io)?;
        dst.write_all(&page_buf).await.map_err(PagedbError::Io)?;
    }

    dst.flush().await.map_err(PagedbError::Io)?;
    dst.sync_all().await.map_err(PagedbError::Io)?;
    Ok(AppliedDeltaPages {
        pages_applied: record_count,
        page_ids,
    })
}

/// Verify that the snapshot's segment directory has exactly the count claimed
/// by its already-authenticated manifest. This runs before apply writes pages
/// or creates any staging files.
pub(crate) async fn validate_snapshot_segment_count(src_path: &Path, expected: u32) -> Result<()> {
    let entries = snapshot_segment_entries(src_path).await?;
    let actual = u32::try_from(entries.len())
        .map_err(|_| PagedbError::snapshot_incompatible("segments_count"))?;
    if actual != expected {
        return Err(PagedbError::snapshot_incompatible("segments_count"));
    }
    Ok(())
}

/// Copy new segment files from the incremental snapshot `src_path/seg/` to the
/// Follower's staging area at `dst_seg_root/.staging/<hex>`. Returns the list
/// of segment IDs that were staged; callers must promote them from staging to
/// live via a journal-backed rename after the header swap.
pub async fn stage_snapshot_segments(
    src_path: &Path,
    dst_seg_root: &Path,
    expected_segment_ids: &BTreeSet<[u8; 16]>,
) -> Result<Vec<[u8; 16]>> {
    let entries = snapshot_segment_entries(src_path).await?;
    let seg_src = src_path.join("seg");
    let actual_segment_ids: BTreeSet<[u8; 16]> = entries
        .iter()
        .map(|name| {
            crate::hex::parse_hex::<16>(name)
                .ok_or_else(|| PagedbError::snapshot_artifact_invalid("segment_file_name"))
        })
        .collect::<Result<_>>()?;
    if &actual_segment_ids != expected_segment_ids {
        return Err(PagedbError::snapshot_artifact_invalid("segments"));
    }

    let staging_dir = dst_seg_root.join(".staging");
    fs::create_dir_all(&staging_dir)
        .await
        .map_err(PagedbError::Io)?;

    let mut staged: Vec<[u8; 16]> = Vec::with_capacity(entries.len());
    let mut copy_buf = vec![0u8; 64 * 1024];

    for name in &entries {
        let segment_id = crate::hex::parse_hex::<16>(name)
            .ok_or_else(|| PagedbError::snapshot_artifact_invalid("segment_file_name"))?;
        let src_file = seg_src.join(name);
        let dst_file = staging_dir.join(name);
        let mut sf = fs::File::open(&src_file).await.map_err(PagedbError::Io)?;
        let mut df = fs::File::create(&dst_file).await.map_err(PagedbError::Io)?;
        loop {
            let n = sf.read(&mut copy_buf).await.map_err(PagedbError::Io)?;
            if n == 0 {
                break;
            }
            df.write_all(&copy_buf[..n])
                .await
                .map_err(PagedbError::Io)?;
        }
        df.flush().await.map_err(PagedbError::Io)?;
        df.sync_all().await.map_err(PagedbError::Io)?;
        staged.push(segment_id);
    }

    Ok(staged)
}

async fn snapshot_segment_entries(src_path: &Path) -> Result<Vec<String>> {
    let seg_src = src_path.join("seg");
    let mut directory = match fs::read_dir(&seg_src).await {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(PagedbError::Io(error)),
    };
    let mut entries = Vec::new();
    while let Some(entry) = directory.next_entry().await.map_err(PagedbError::Io)? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(PagedbError::snapshot_incompatible("segments"));
        };
        crate::hex::parse_hex::<16>(name)
            .ok_or_else(|| PagedbError::snapshot_incompatible("segments"))?;
        entries.push(name.to_owned());
    }
    Ok(entries)
}
