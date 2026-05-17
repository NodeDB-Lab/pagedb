//! main.db A/B header protocol. Two header pages (page 0 = slot A, page 1 =
//! slot B) double-buffer the durable B+ tree root pointer, commit id, nonce
//! anchor, and apply-journal pointer. Every commit writes to the inactive
//! slot and bumps `seq`; the next open picks the slot with the greater valid
//! `seq` (HK-MAC-verified). A torn write to one slot leaves the other intact.

use crate::Result;
use crate::crypto::keys::DerivedKey;
use crate::errors::{CorruptionDetail, PagedbError};
use crate::pager::format::structural_header::{
    MainDbHeaderFields, decode_main_db_header, encode_main_db_header,
};
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

/// Which header slot is the authoritative current header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveSlot {
    A,
    B,
}

impl ActiveSlot {
    /// Slot index in the file: A = page 0, B = page 1.
    #[must_use]
    pub fn page_id(self) -> u64 {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Bootstrap a fresh main.db. Creates the file (fails if it already exists),
/// writes the supplied initial header into slot A with the caller's `seq`,
/// and leaves slot B all-zero. The all-zero slot fails the magic check at
/// open, so slot A wins as the only verifiable header.
///
/// Caller is responsible for setting `initial.seq` (typically 1 for a fresh
/// DB) and every other field. The `page_size_log2` field must match
/// `page_size`.
pub async fn bootstrap_header<V: Vfs>(
    vfs: &V,
    path: &str,
    hk: &DerivedKey,
    initial: &MainDbHeaderFields,
    page_size: usize,
) -> Result<()> {
    let bytes = encode_main_db_header(initial, hk, page_size)?;
    let mut f = vfs.open(path, OpenMode::CreateNew).await?;
    // Slot A at offset 0.
    f.write_at(0, &bytes).await?;
    // Slot B at offset page_size — write a zero-filled page so the slot is
    // materialised on disk. Decode of a zero buffer fails the magic check
    // and returns `Corruption(HeaderUnverifiable)`, which `open_header`
    // treats as "this slot is unverifiable; skip it."
    let zero = vec![0u8; page_size];
    let page_size_u64 = u64::try_from(page_size)
        .map_err(|_| PagedbError::Io(std::io::Error::other("page_size > u64")))?;
    f.write_at(page_size_u64, &zero).await?;
    f.sync().await?;
    // Make the directory entry for the newly created file durable so a
    // power loss immediately after creation does not lose the file.
    let dir = std::path::Path::new(path.trim_start_matches('/'))
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or(".");
    // Use "/" as the VFS root directory when path has no parent component.
    let dir_path = if dir == "." { "/" } else { dir };
    vfs.sync_dir(dir_path).await?;
    Ok(())
}

/// Open an existing main.db, return the active header fields and which slot
/// they came from.
///
/// Reads both slots; verifies each via HK-MAC; picks the one with the
/// greater `seq`. If only one verifies, it wins. If neither verifies, returns
/// `Corruption(HeaderUnverifiable)` — unrecoverable from inside the header
/// layer.
pub async fn open_header<V: Vfs>(
    vfs: &V,
    path: &str,
    hk: &DerivedKey,
    page_size: usize,
) -> Result<(MainDbHeaderFields, ActiveSlot)> {
    let f = vfs.open(path, OpenMode::ReadWrite).await?;
    let mut buf_a = vec![0u8; page_size];
    let mut buf_b = vec![0u8; page_size];
    let _ = f.read_at(0, &mut buf_a).await?;
    let page_size_u64 = u64::try_from(page_size)
        .map_err(|_| PagedbError::Io(std::io::Error::other("page_size > u64")))?;
    let _ = f.read_at(page_size_u64, &mut buf_b).await?;
    let a = decode_main_db_header(&buf_a, hk, page_size).ok();
    let b = decode_main_db_header(&buf_b, hk, page_size).ok();
    match (a, b) {
        (Some(a), Some(b)) => {
            if a.seq >= b.seq {
                Ok((a, ActiveSlot::A))
            } else {
                Ok((b, ActiveSlot::B))
            }
        }
        (Some(a), None) => Ok((a, ActiveSlot::A)),
        (None, Some(b)) => Ok((b, ActiveSlot::B)),
        (None, None) => Err(PagedbError::corruption(
            CorruptionDetail::HeaderUnverifiable,
        )),
    }
}

/// Commit a new header. Writes `fields` into the *inactive* slot (toggle of
/// `previous`), fsyncs, and returns the new active slot.
///
/// `fields.seq` must be strictly greater than the value in the slot it
/// supersedes — that is the caller's responsibility (typically `prev_seq +
/// 1`). The header layer does not bump `seq` automatically because the
/// transaction layer owns sequencing.
pub async fn commit_header<V: Vfs>(
    vfs: &V,
    path: &str,
    hk: &DerivedKey,
    fields: &MainDbHeaderFields,
    previous: ActiveSlot,
    page_size: usize,
) -> Result<ActiveSlot> {
    let next = previous.other();
    let bytes = encode_main_db_header(fields, hk, page_size)?;
    let mut f = vfs.open(path, OpenMode::ReadWrite).await?;
    let offset = u64::try_from(page_size)
        .ok()
        .map(|s| next.page_id().saturating_mul(s))
        .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset arithmetic overflow")))?;
    f.write_at(offset, &bytes).await?;
    f.sync().await?;
    // No `sync_dir` here: a header rewrite is a data write to an existing,
    // already-durable inode (main.db). Architecture §883 requires `sync_dir`
    // only after rename/remove/create, none of which happen on the commit
    // path. (Initial create of main.db is sync_dir'd at open time.)
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::kdf::{derive_hk, derive_mk};
    use crate::vfs::memory::MemVfs;
    use crate::{CommitId, Result};

    fn sample(seq: u64) -> MainDbHeaderFields {
        MainDbHeaderFields {
            format_version: 1,
            cipher_id: 1,
            page_size_log2: 12,
            flags: 0,
            file_id: [0xAB; 16],
            kek_salt: [0xCD; 16],
            mk_epoch: 0,
            seq,
            active_root_page_id: 4,
            active_root_txn_id: 1,
            counter_anchor: 0,
            commit_id: CommitId(0),
            free_list_root: [0; 16],
            catalog_root: [0; 16],
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            restore_mode: 0,
            next_page_id: 4,
            commit_retain_policy_tag: 0,
            commit_retain_policy_value: 1024,
        }
    }

    fn hk() -> DerivedKey {
        let mk = derive_mk(&[7u8; 32], &[0u8; 16], 0).unwrap();
        derive_hk(&mk).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_then_open_round_trip() -> Result<()> {
        let vfs = MemVfs::new();
        let hk = hk();
        let initial = sample(1);
        bootstrap_header(&vfs, "/main.db", &hk, &initial, 4096).await?;
        let (got, slot) = open_header(&vfs, "/main.db", &hk, 4096).await?;
        assert_eq!(got, initial);
        assert_eq!(slot, ActiveSlot::A);
        Ok(())
    }
}
