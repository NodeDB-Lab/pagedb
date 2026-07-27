//! Staging the segment files an incremental snapshot carries.
//!
//! New segment files land in `seg/.staging/<hex>` and are promoted to `seg/`
//! by journal-backed renames after the staged `main.db` image is swapped in,
//! so a failed apply leaves only staging entries the next open collects.

use std::collections::BTreeSet;
use std::path::Path;

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::Result;
use crate::errors::PagedbError;

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
/// live via a journal-backed rename after the image swap.
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
