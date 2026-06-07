//! Free helper functions shared across the `Db` submodules: page-size encoding,
//! VFS root extraction, header peeking, lease-id generation, and the
//! writer-open stale-reader-pin cleanup.

use std::sync::Arc;

use crate::btree::BTree;
use crate::catalog::codec::Catalog;
use crate::crypto::kdf::{derive_hk, derive_mk};
use crate::errors::PagedbError;
use crate::pager::Pager;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;
use crate::{CommitId, RealmId, Result};

use super::core::{WriterState, encode_root_ref};

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

/// Extract the filesystem root path from a `Vfs` instance. Returns
/// `Err(Unsupported)` for in-memory or non-filesystem VFS backends.
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

/// Generate a unique lease ID for a reader pin using a monotonic counter mixed
/// with the current Unix timestamp. Not cryptographically random, but uniqueness
/// within a process lifetime is sufficient for the pin-row key.
pub(super) fn next_lease_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering as Ord};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ord::Relaxed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            #[allow(clippy::cast_possible_truncation)]
            let v = d.as_nanos() as u64; // lower 64 bits sufficient for uniqueness
            v
        });
    ts ^ (seq.wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

/// Scan the catalog for durable reader-pin rows that are either stale (written
/// by the current PID from a previous process incarnation) or expired by wall
/// clock. Delete all such rows in a single bulk catalog commit. Called at
/// writer-open time to recover from reader crashes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cleanup_stale_reader_pins<V: Vfs + Clone>(
    pager: &Arc<Pager<V>>,
    vfs: &Arc<V>,
    main_db_path: &str,
    hk: &crate::crypto::keys::DerivedKey,
    realm_id: RealmId,
    page_size: usize,
    cipher_id: crate::crypto::CipherId,
    file_id: [u8; 16],
    kek_salt: [u8; 16],
    mk_epoch_val: u64,
    state: &mut WriterState,
) -> Result<()> {
    if state.catalog_root_page_id == 0 {
        return Ok(());
    }
    let now = crate::txn::read::unix_now_seconds();
    let own_pid = std::process::id();
    let tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        page_size,
    );
    let start = crate::catalog::codec::Catalog::reader_pin_range_start();
    let end = crate::catalog::codec::Catalog::reader_pin_range_end();
    let rows = tree.collect_range(&start, &end).await?;

    let stale_keys: Vec<Vec<u8>> = rows
        .into_iter()
        .filter_map(|(k, v)| {
            // Key layout: [0x06] || pid_u32_be[4] || lease_id_u64_be[8]
            if k.len() < 13 {
                return Some(k);
            }
            let mut pid_buf = [0u8; 4];
            pid_buf.copy_from_slice(&k[1..5]);
            let row_pid = u32::from_be_bytes(pid_buf);
            // Own-PID rows from prior incarnation (crash without cleanup).
            if row_pid == own_pid {
                return Some(k);
            }
            // Expired rows.
            if let Ok(pv) = Catalog::decode_reader_pin(&v) {
                if pv.expires_unix_seconds < now {
                    return Some(k);
                }
            }
            None
        })
        .collect();

    if stale_keys.is_empty() {
        return Ok(());
    }

    let mut cat_tree = BTree::open(
        pager.clone(),
        realm_id,
        state.catalog_root_page_id,
        state.next_page_id,
        page_size,
    );
    for k in &stale_keys {
        let _ = cat_tree.delete(k).await;
    }
    cat_tree.flush().await?;
    let new_cat_root = cat_tree.root_page_id();
    let new_next = cat_tree.next_page_id().max(state.next_page_id);
    let new_commit_id = state.latest_commit_id + 1;
    let new_seq = state.seq + 1;
    let counter_anchor = pager.pending_anchor();
    let catalog_root_bytes = encode_root_ref(new_cat_root, new_commit_id);
    let fields = MainDbHeaderFields {
        format_version: 1,
        cipher_id: cipher_id.as_byte(),
        page_size_log2: page_size_log2(page_size)?,
        flags: 0,
        file_id,
        kek_salt,
        mk_epoch: mk_epoch_val,
        seq: new_seq,
        active_root_page_id: state.root_page_id,
        active_root_txn_id: state.latest_commit_id,
        counter_anchor,
        commit_id: CommitId(new_commit_id),
        free_list_root: [0u8; 16],
        catalog_root: catalog_root_bytes,
        apply_journal_root_page_id: 0,
        apply_journal_root_version: 0,
        commit_history_root_page_id: state.commit_history_root_page_id,
        commit_history_root_version: state.commit_history_root_version,
        restore_mode: 0,
        next_page_id: new_next,
        commit_retain_policy_tag: 0,
        commit_retain_policy_value: 0,
    };
    let new_slot = commit_header(
        &**vfs,
        main_db_path,
        hk,
        &fields,
        state.active_slot,
        page_size,
    )
    .await?;
    pager.commit_anchor(counter_anchor)?;
    state.catalog_root_page_id = new_cat_root;
    state.next_page_id = new_next;
    state.active_slot = new_slot;
    state.latest_commit_id = new_commit_id;
    state.seq = new_seq;
    Ok(())
}
