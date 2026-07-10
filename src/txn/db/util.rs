//! Free helper functions shared across DB submodules: page-size encoding, VFS
//! root extraction, and header peeking.

use crate::Result;
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::errors::PagedbError;
use crate::vfs::Vfs;

pub(super) fn page_size_log2(page_size: usize) -> Result<u8> {
    match page_size {
        4096 => Ok(12),
        8192 => Ok(13),
        16384 => Ok(14),
        32768 => Ok(15),
        65536 => Ok(16),
        _ => Err(PagedbError::Unsupported),
    }
}

/// Extract the filesystem root path from a `Vfs` instance.
///
/// Returns `Unsupported` for in-memory or non-filesystem VFS backends.
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn get_vfs_root<V: Vfs + Clone>(vfs: &V) -> Result<std::path::PathBuf> {
    vfs.root_path()
        .map(std::path::Path::to_path_buf)
        .ok_or(PagedbError::Unsupported)
}

/// Read the `restore_mode` byte from the on-disk header of an existing
/// `main.db` without fully opening the database.
///
/// Tries both the A and B header slots. Returns the `restore_mode` byte from
/// the first slot that verifies successfully under the given KEK.
pub(super) async fn peek_restore_mode<V: Vfs + Clone>(
    vfs: &V,
    kek: &[u8; 32],
    page_size: usize,
) -> Result<u8> {
    use crate::vfs::VfsFile;
    use crate::vfs::types::OpenMode;

    let f = vfs.open("/main.db", OpenMode::Read).await?;
    let mut buf_a = vec![0u8; page_size];
    let mut buf_b = vec![0u8; page_size];
    f.read_at(0, &mut buf_a).await?;
    let page_size_u64 = u64::try_from(page_size)
        .map_err(|_| PagedbError::Io(std::io::Error::other("page_size > u64")))?;
    f.read_at(page_size_u64, &mut buf_b).await?;
    drop(f);

    for buf in [&buf_a, &buf_b] {
        if buf.len() < 56 {
            continue;
        }
        let mut kek_salt = [0u8; 16];
        kek_salt.copy_from_slice(&buf[32..48]);
        let mut ep_bytes = [0u8; 8];
        ep_bytes.copy_from_slice(&buf[48..56]);
        let mk_epoch = u64::from_le_bytes(ep_bytes);
        let Ok(mk) = derive_mk(kek, &kek_salt, mk_epoch) else {
            continue;
        };
        let Ok(hk) = derive_hk(&mk) else {
            continue;
        };
        if let Ok(fields) =
            crate::pager::format::structural_header::decode_main_db_header(buf, &hk, page_size)
        {
            return Ok(fields.restore_mode);
        }
    }
    Err(PagedbError::corruption(
        crate::errors::CorruptionDetail::HeaderUnverifiable,
    ))
}
