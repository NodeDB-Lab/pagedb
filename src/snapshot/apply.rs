//! `apply_incremental`: reads a delta snapshot stream and applies it to a
//! Follower handle by writing pages directly and then swapping the A/B header.

#![cfg(not(target_arch = "wasm32"))]

use std::path::Path;

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::Result;
use crate::errors::PagedbError;

/// Apply an incremental snapshot directory (`src_path`) to the Follower's
/// `main.db` file at `main_db_path` (absolute filesystem path). Returns stats.
///
/// Crash-safety: pages are written first, then the header swap happens via the
/// normal `commit_header` path in `Db::apply_incremental`.
pub async fn apply_delta_pages(
    src_path: &Path,
    dst_main_db_path: &Path,
    page_size: usize,
) -> Result<u64> {
    let delta_path = src_path.join("pages.delta");
    let mut delta = match fs::File::open(&delta_path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(PagedbError::Io(e)),
    };

    let mut dst = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dst_main_db_path)
        .await
        .map_err(PagedbError::Io)?;

    let mut pages_applied: u64 = 0;
    let mut id_buf = [0u8; 8];
    let mut page_buf = vec![0u8; page_size];

    loop {
        // Read page_id (8 bytes BE).
        match delta.read_exact(&mut id_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(PagedbError::Io(e)),
        }
        let page_id = u64::from_be_bytes(id_buf);

        // Read page bytes.
        match delta.read_exact(&mut page_buf).await {
            Ok(_) => {}
            Err(e) => return Err(PagedbError::Io(e)),
        }

        // Write page to main.db at the correct offset.
        let offset = page_id
            .checked_mul(page_size as u64)
            .ok_or_else(|| PagedbError::Io(std::io::Error::other("page offset overflow")))?;
        dst.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(PagedbError::Io)?;
        dst.write_all(&page_buf).await.map_err(PagedbError::Io)?;
        pages_applied += 1;
    }

    dst.flush().await.map_err(PagedbError::Io)?;
    dst.sync_all().await.map_err(PagedbError::Io)?;
    Ok(pages_applied)
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
) -> Result<Vec<[u8; 16]>> {
    let entries = snapshot_segment_entries(src_path).await?;
    let seg_src = src_path.join("seg");

    let staging_dir = dst_seg_root.join(".staging");
    fs::create_dir_all(&staging_dir)
        .await
        .map_err(PagedbError::Io)?;

    let mut staged: Vec<[u8; 16]> = Vec::with_capacity(entries.len());
    let mut copy_buf = vec![0u8; 64 * 1024];

    for name in &entries {
        // Each name in seg/ is 32 hex chars encoding the 16-byte segment id.
        let segment_id = crate::hex::parse_hex::<16>(name).ok_or_else(|| {
            PagedbError::corruption(crate::errors::CorruptionDetail::HeaderUnverifiable)
        })?;
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
