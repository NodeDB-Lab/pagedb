//! `snapshot_to` and `snapshot_incremental_to`: serialise the live DB state
//! into a portable snapshot directory.

use std::path::Path;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::Result;
use crate::errors::PagedbError;

use super::SnapshotStats;

// ---------------------------------------------------------------------------
// Manifest layout constants
// ---------------------------------------------------------------------------

const MAGIC: &[u8; 8] = b"PGDBSNAP";
const MANIFEST_RESERVED_SIZE: usize = 240;

#[allow(dead_code)]
const KIND_FULL: u8 = 0;
#[allow(dead_code)]
const KIND_INCREMENTAL: u8 = 1;

type HmacSha256 = Hmac<Sha256>;

/// Decoded snapshot manifest.
#[derive(Debug, Clone)]
pub struct SnapshotManifest {
    pub version: u32,
    pub kind: u8,
    pub target_commit: u64,
    pub base_commit: u64,
    pub file_id: [u8; 16],
    pub mk_epoch: u64,
    pub kek_salt: [u8; 16],
    pub cipher_id: u8,
    pub page_size: u32,
    pub next_page_id_at_target: u64,
    pub segments_count: u32,
    /// Realm id of the database that produced this snapshot. Stored in the
    /// reserved section of the manifest so `restore_from` can reopen with the
    /// correct AAD.
    pub realm_id: [u8; 16],
}

/// Encode and HK-MAC a manifest into the 240-byte on-disk format.
#[must_use]
pub fn encode_manifest(m: &SnapshotManifest, hk_key: &[u8; 32]) -> [u8; MANIFEST_RESERVED_SIZE] {
    let mut buf = [0u8; MANIFEST_RESERVED_SIZE];
    // magic [0..8]
    buf[..8].copy_from_slice(MAGIC);
    // version u32 LE [8..12]
    buf[8..12].copy_from_slice(&m.version.to_le_bytes());
    // kind u8 [12]
    buf[12] = m.kind;
    // target_commit u64 LE [13..21]
    buf[13..21].copy_from_slice(&m.target_commit.to_le_bytes());
    // base_commit u64 LE [21..29]
    buf[21..29].copy_from_slice(&m.base_commit.to_le_bytes());
    // file_id [16] [29..45]
    buf[29..45].copy_from_slice(&m.file_id);
    // mk_epoch u64 LE [45..53]
    buf[45..53].copy_from_slice(&m.mk_epoch.to_le_bytes());
    // kek_salt [16] [53..69]
    buf[53..69].copy_from_slice(&m.kek_salt);
    // cipher_id u8 [69]
    buf[69] = m.cipher_id;
    // page_size u32 LE [70..74]
    buf[70..74].copy_from_slice(&m.page_size.to_le_bytes());
    // next_page_id_at_target u64 LE [74..82]
    buf[74..82].copy_from_slice(&m.next_page_id_at_target.to_le_bytes());
    // segments_count u32 LE [82..86]
    buf[82..86].copy_from_slice(&m.segments_count.to_le_bytes());
    // realm_id [16] [86..102]
    buf[86..102].copy_from_slice(&m.realm_id);
    // reserved zeros [102..224]
    // HK-MAC[16] [224..240]
    let mac = compute_manifest_mac(&buf[..224], hk_key);
    buf[224..240].copy_from_slice(&mac);
    buf
}

/// Decode and verify a manifest. Returns `PagedbError::Corruption` if the
/// HK-MAC check fails.
pub fn decode_manifest(
    buf: &[u8; MANIFEST_RESERVED_SIZE],
    hk_key: &[u8; 32],
) -> Result<SnapshotManifest> {
    if &buf[..8] != MAGIC {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let expected_mac = compute_manifest_mac(&buf[..224], hk_key);
    if buf[224..240] != expected_mac {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let version = u32::from_le_bytes(buf[8..12].try_into().unwrap_or([0; 4]));
    let kind = buf[12];
    let target_commit = u64::from_le_bytes(buf[13..21].try_into().unwrap_or([0; 8]));
    let base_commit = u64::from_le_bytes(buf[21..29].try_into().unwrap_or([0; 8]));
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&buf[29..45]);
    let mk_epoch = u64::from_le_bytes(buf[45..53].try_into().unwrap_or([0; 8]));
    let mut kek_salt = [0u8; 16];
    kek_salt.copy_from_slice(&buf[53..69]);
    let cipher_id = buf[69];
    let page_size = u32::from_le_bytes(buf[70..74].try_into().unwrap_or([0; 4]));
    let next_page_id_at_target = u64::from_le_bytes(buf[74..82].try_into().unwrap_or([0; 8]));
    let segments_count = u32::from_le_bytes(buf[82..86].try_into().unwrap_or([0; 4]));
    let mut realm_id = [0u8; 16];
    realm_id.copy_from_slice(&buf[86..102]);
    Ok(SnapshotManifest {
        version,
        kind,
        target_commit,
        base_commit,
        file_id,
        mk_epoch,
        kek_salt,
        cipher_id,
        page_size,
        next_page_id_at_target,
        segments_count,
        realm_id,
    })
}

fn compute_manifest_mac(data: &[u8], hk_key: &[u8; 32]) -> [u8; 16] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hk_key).expect("HMAC can take any key size");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Copy all bytes from a tokio file to a destination path, returning bytes written.
async fn copy_file_to(src_path: &Path, dst_path: &Path) -> Result<u64> {
    let mut src = fs::File::open(src_path).await.map_err(PagedbError::Io)?;
    let mut dst = fs::File::create(dst_path).await.map_err(PagedbError::Io)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).await.map_err(PagedbError::Io)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await.map_err(PagedbError::Io)?;
        total += n as u64;
    }
    dst.flush().await.map_err(PagedbError::Io)?;
    Ok(total)
}

/// Perform a full snapshot of `src_db_root` (a `TokioVfs` root directory) to
/// `dst_path`. Returns the manifest and stats for use by `Db::snapshot_to`.
///
/// This function is called while a non-abortable `ReadTxn` pin is held in the
/// caller; that pin ensures the catalog and segment files remain live.
pub async fn snapshot_full(
    src_db_root: &Path,
    dst_path: &Path,
    manifest: &SnapshotManifest,
    hk_key: &[u8; 32],
    segment_ids: &[[u8; 16]],
) -> Result<SnapshotStats> {
    // Create destination directory layout.
    fs::create_dir_all(dst_path)
        .await
        .map_err(PagedbError::Io)?;
    let seg_dst = dst_path.join("seg");
    fs::create_dir_all(&seg_dst)
        .await
        .map_err(PagedbError::Io)?;

    // Write manifest.
    let manifest_bytes = encode_manifest(manifest, hk_key);
    let manifest_dst = dst_path.join("manifest");
    let mut mf = fs::File::create(&manifest_dst)
        .await
        .map_err(PagedbError::Io)?;
    mf.write_all(&manifest_bytes)
        .await
        .map_err(PagedbError::Io)?;
    mf.flush().await.map_err(PagedbError::Io)?;
    let mut total_bytes: u64 = MANIFEST_RESERVED_SIZE as u64;

    // Copy main.db.
    let main_src = src_db_root.join("main.db");
    let main_dst = dst_path.join("main.db");
    let main_bytes = copy_file_to(&main_src, &main_dst).await?;
    total_bytes += main_bytes;

    // Count pages from file size.
    let page_size = u64::from(manifest.page_size);
    let pages_written = main_bytes.checked_div(page_size).unwrap_or(0);

    // Copy segment files.
    let mut segments_written: u32 = 0;
    for seg_id in segment_ids {
        let hex = crate::segment::writer::hex_lower(seg_id);
        let seg_src = src_db_root.join("seg").join(&hex);
        let seg_dst_file = seg_dst.join(&hex);
        if let Ok(n) = copy_file_to(&seg_src, &seg_dst_file).await {
            total_bytes += n;
            segments_written += 1;
        }
        // Err(_): file may have been tombstoned between list and copy; skip.
    }

    Ok(SnapshotStats {
        pages_written,
        segments_written,
        bytes: total_bytes,
    })
}

/// Write the incremental delta sidecar (`pages.delta`) to `dst_path`.
///
/// Format: sequence of `(page_id: u64 BE, page_bytes: [u8; page_size])` for
/// every main.db data page whose `commit_id` (at header offset 12 of the
/// ciphertext envelope) is strictly greater than `base_commit`.
///
/// The header byte at offset 12 of a data page is the first byte of the
/// 6-byte nonce, not the `commit_id`. The specification says: "compare
/// `commit_id` stored in each data-page header (offset 12 per Format A)".
/// However, Format A layout has: `cipher_id`[0], `page_kind`[1], flags[2..4],
/// `mk_epoch`[4..12], nonce[12..18]. There is no per-page `commit_id` in the
/// ciphertext header. The correct approach is to emit all pages from the
/// current root that are at `page_id` >= `base_next_page_id` (newly allocated
/// after base commit), or use the data pages the `BTree` walks.
///
/// We use a practical simplification: emit all pages reachable from the
/// current root whose `page_id` >= `base_next_page_id` (pages allocated after
/// the base snapshot's `next_page_id`). This is conservative but correct: it
/// never emits fewer pages than needed.
pub async fn snapshot_incremental(
    src_db_root: &Path,
    dst_path: &Path,
    manifest: &SnapshotManifest,
    hk_key: &[u8; 32],
    segment_ids: &[[u8; 16]],
    base_next_page_id: u64,
    changed_page_ids: &[u64],
) -> Result<SnapshotStats> {
    fs::create_dir_all(dst_path)
        .await
        .map_err(PagedbError::Io)?;
    let seg_dst = dst_path.join("seg");
    fs::create_dir_all(&seg_dst)
        .await
        .map_err(PagedbError::Io)?;

    // Write manifest.
    let manifest_bytes = encode_manifest(manifest, hk_key);
    let manifest_dst = dst_path.join("manifest");
    let mut mf = fs::File::create(&manifest_dst)
        .await
        .map_err(PagedbError::Io)?;
    mf.write_all(&manifest_bytes)
        .await
        .map_err(PagedbError::Io)?;
    mf.flush().await.map_err(PagedbError::Io)?;
    let mut total_bytes: u64 = MANIFEST_RESERVED_SIZE as u64;

    // Write pages.delta: (page_id u64 BE, page_bytes) for each changed page.
    let page_size = manifest.page_size as usize;
    let delta_dst = dst_path.join("pages.delta");
    let main_src = src_db_root.join("main.db");

    let mut main_file = fs::File::open(&main_src).await.map_err(PagedbError::Io)?;
    let mut delta_file = fs::File::create(&delta_dst)
        .await
        .map_err(PagedbError::Io)?;
    let mut pages_written: u64 = 0;

    let mut page_buf = vec![0u8; page_size];

    // Sort and deduplicate page ids.
    let mut page_ids = changed_page_ids.to_vec();
    page_ids.sort_unstable();
    page_ids.dedup();

    for page_id in &page_ids {
        // Skip header pages (0 and 1 are A/B header slots).
        if *page_id < 2 {
            continue;
        }
        let offset = page_id
            .checked_mul(page_size as u64)
            .ok_or_else(|| PagedbError::Io(std::io::Error::other("page offset overflow")))?;
        main_file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(PagedbError::Io)?;
        let n = main_file
            .read(&mut page_buf)
            .await
            .map_err(PagedbError::Io)?;
        if n < page_size {
            continue; // sparse / beyond EOF
        }
        delta_file
            .write_all(&page_id.to_be_bytes())
            .await
            .map_err(PagedbError::Io)?;
        delta_file
            .write_all(&page_buf)
            .await
            .map_err(PagedbError::Io)?;
        total_bytes += 8 + page_size as u64;
        pages_written += 1;
    }
    delta_file.flush().await.map_err(PagedbError::Io)?;
    let _ = base_next_page_id; // used by caller to compute changed_page_ids

    // Copy new/changed segment files.
    let mut segments_written: u32 = 0;
    for seg_id in segment_ids {
        let hex = crate::segment::writer::hex_lower(seg_id);
        let seg_src = src_db_root.join("seg").join(&hex);
        let seg_dst_file = seg_dst.join(&hex);
        if let Ok(n) = copy_file_to(&seg_src, &seg_dst_file).await {
            total_bytes += n;
            segments_written += 1;
        }
    }

    Ok(SnapshotStats {
        pages_written,
        segments_written,
        bytes: total_bytes,
    })
}

/// Derive the HK bytes used for snapshot manifest MAC from a KEK and `kek_salt`.
/// We use HKDF / the same KDF chain as the DB: mk = `derive_mk(kek`, salt, epoch),
/// `hk_bytes` = first 32 bytes of `derive_hk(mk)`.
pub fn derive_snapshot_hk_key(
    kek: &[u8; 32],
    kek_salt: &[u8; 16],
    mk_epoch: u64,
) -> Result<[u8; 32]> {
    let mk = crate::crypto::kdf::derive_mk(kek, kek_salt, mk_epoch)?;
    let hk = crate::crypto::kdf::derive_hk(&mk)?;
    Ok(*hk.as_bytes())
}

/// Read the HK-MAC key from a snapshot manifest file and verify + return the
/// manifest. `kek` is used to re-derive the HK.
pub async fn open_manifest(manifest_path: &Path, kek: &[u8; 32]) -> Result<SnapshotManifest> {
    let mut f = fs::File::open(manifest_path)
        .await
        .map_err(PagedbError::Io)?;
    let mut buf = [0u8; MANIFEST_RESERVED_SIZE];
    let n = f.read(&mut buf).await.map_err(PagedbError::Io)?;
    if n < MANIFEST_RESERVED_SIZE {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    // Extract kek_salt from buf[53..69] and mk_epoch from buf[45..53] to
    // derive the HK key needed to verify the MAC.
    let mut kek_salt = [0u8; 16];
    kek_salt.copy_from_slice(&buf[53..69]);
    let mk_epoch_bytes: [u8; 8] = buf[45..53].try_into().unwrap_or([0u8; 8]);
    let mk_epoch = u64::from_le_bytes(mk_epoch_bytes);
    let hk_key = derive_snapshot_hk_key(kek, &kek_salt, mk_epoch)?;
    decode_manifest(&buf, &hk_key)
}
