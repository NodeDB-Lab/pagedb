//! Apply-journal replay. The apply journal records the file-system side
//! effects a future `apply_incremental` operation must perform after the
//! new A/B header is durable. On crash mid-apply, the journal lets the
//! next open re-execute pending side effects deterministically.
//!
//! # Sidecar layout
//!
//! The journal is a standalone AEAD-authenticated sidecar file at
//! `applyjournal/<hex(journal_id)>`, written through the Pager (same key
//! schedule, cipher-agility, and `RealmId`-in-AAD binding as every other
//! persistent page). It is *not* a `main.db` page, so it consumes no free-list
//! page and never perturbs the receiver's `free_list_root`; and it is *not*
//! under `seg/`, so catalog reconciliation never mistakes it for a segment.
//!
//! Each apply allocates a fresh, never-reused `journal_id` (so per-file nonce
//! generators can start from their seed without ever colliding under one key).
//! The 16-byte id is carried in the A/B header's `apply_journal_root` fields
//! (`page_id` = id bytes 0..8, `version` = id bytes 8..16); an all-zero id
//! means "no apply in flight".
//!
//! Because the sidecar is written and fsynced *before* the header swap (the
//! durable commit point), the record may span an arbitrary number of pages —
//! there is no single-page ceiling on the promotion/tombstone set.
//!
//! # Record stream
//!
//! The concatenation of every sidecar page body, in page order, is:
//!
//! ```text
//! stream_len : u32 LE   (length of the record bytes that follow)
//! record     : [u8; stream_len]
//!   target_commit_id : u64 LE
//!   action_count     : u32 LE
//!   actions[]        : each action:
//!     kind           : u8  (0x01 = Promote, 0x02 = Tombstone)
//!     segment_id     : [u8; 16]
//!     if kind == Tombstone:
//!       tombstone_commit_id : u64 LE
//! (trailing zero padding to the end of the last page)
//! ```
//!
//! `stream_len` makes the record self-delimiting: trailing padding (and any
//! stale bytes from a shorter prior journal that happened to reuse the file)
//! are never mistaken for actions.

use crate::Result;
use crate::errors::PagedbError;
use crate::pager::format::data_page::body_capacity;
use crate::pager::format::page_kind::PageKind;
use crate::vfs::Vfs;

/// Length prefix (`stream_len`) that precedes the record in the page stream.
const STREAM_PREFIX_LEN: usize = 4;

/// A single side-effect action the apply journal records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalAction {
    /// Rename `seg/.staging/<hex(segment_id)>` to `seg/<hex(segment_id)>`.
    Promote { segment_id: [u8; 16] },
    /// Rename `seg/<hex(segment_id)>` to
    /// `seg/.tombstone/<hex(segment_id)>.<tombstone_commit_id>`.
    Tombstone {
        segment_id: [u8; 16],
        tombstone_commit_id: u64,
    },
}

/// The decoded payload of an apply-journal sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyJournalRecord {
    /// The `apply_incremental` commit that wrote this journal entry.
    pub target_commit_id: u64,
    /// Ordered list of side effects to replay.
    pub actions: Vec<JournalAction>,
}

/// Encode the record (without the stream-length prefix) into its wire bytes.
#[must_use]
pub fn encode_record(record: &ApplyJournalRecord) -> Vec<u8> {
    let actions_len: usize = record
        .actions
        .iter()
        .map(|action| match action {
            // kind byte + segment_id
            JournalAction::Promote { .. } => 17,
            // kind byte + segment_id + tombstone_commit_id
            JournalAction::Tombstone { .. } => 25,
        })
        .sum();
    let mut buf = Vec::with_capacity(12 + actions_len);
    buf.extend_from_slice(&record.target_commit_id.to_le_bytes());
    let count = u32::try_from(record.actions.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&count.to_le_bytes());
    for action in &record.actions {
        match action {
            JournalAction::Promote { segment_id } => {
                buf.push(0x01);
                buf.extend_from_slice(segment_id);
            }
            JournalAction::Tombstone {
                segment_id,
                tombstone_commit_id,
            } => {
                buf.push(0x02);
                buf.extend_from_slice(segment_id);
                buf.extend_from_slice(&tombstone_commit_id.to_le_bytes());
            }
        }
    }
    buf
}

/// Split a record into a sequence of page-body buffers, each exactly
/// `body_capacity(page_size)` bytes, ready to stage as sidecar pages 0..N.
/// The first four bytes of the stream are the record length; the tail of the
/// final page is zero-padded.
pub fn encode_journal_pages(record: &ApplyJournalRecord, page_size: usize) -> Result<Vec<Vec<u8>>> {
    let cap = body_capacity(page_size);
    if cap <= STREAM_PREFIX_LEN {
        return Err(PagedbError::Unsupported);
    }
    let record_bytes = encode_record(record);
    let stream_len = u32::try_from(record_bytes.len()).map_err(|_| PagedbError::PayloadTooLarge)?;
    let total = STREAM_PREFIX_LEN + record_bytes.len();
    let page_count = total.div_ceil(cap);

    let mut stream = vec![0u8; page_count * cap];
    stream[..STREAM_PREFIX_LEN].copy_from_slice(&stream_len.to_le_bytes());
    stream[STREAM_PREFIX_LEN..total].copy_from_slice(&record_bytes);

    Ok(stream.chunks(cap).map(<[u8]>::to_vec).collect())
}

/// Number of sidecar pages a stream of `record_byte_len` record bytes occupies.
fn page_count_for(record_byte_len: usize, page_size: usize) -> usize {
    let cap = body_capacity(page_size);
    (STREAM_PREFIX_LEN + record_byte_len).div_ceil(cap)
}

/// Decode a record from the in-order concatenation of every sidecar page body.
pub fn decode_journal_stream(stream: &[u8]) -> Result<ApplyJournalRecord> {
    if stream.len() < STREAM_PREFIX_LEN {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let mut p4 = [0u8; 4];
    p4.copy_from_slice(&stream[..STREAM_PREFIX_LEN]);
    let stream_len = u32::from_le_bytes(p4) as usize;
    let end = STREAM_PREFIX_LEN
        .checked_add(stream_len)
        .filter(|e| *e <= stream.len())
        .ok_or_else(|| {
            PagedbError::corruption(crate::errors::CorruptionDetail::HeaderUnverifiable)
        })?;
    decode_record(&stream[STREAM_PREFIX_LEN..end])
}

/// Decode an `ApplyJournalRecord` from its wire bytes (no length prefix).
/// Returns `Err(Corruption)` if the data is malformed.
pub fn decode_record(buf: &[u8]) -> Result<ApplyJournalRecord> {
    if buf.len() < 12 {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let mut off = 0;
    let mut b8 = [0u8; 8];
    b8.copy_from_slice(&buf[off..off + 8]);
    let target_commit_id = u64::from_le_bytes(b8);
    off += 8;
    let mut b4 = [0u8; 4];
    b4.copy_from_slice(&buf[off..off + 4]);
    let action_count = u32::from_le_bytes(b4) as usize;
    off += 4;

    let mut actions = Vec::with_capacity(action_count);
    for _ in 0..action_count {
        if off >= buf.len() {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let kind = buf[off];
        off += 1;
        if off + 16 > buf.len() {
            return Err(PagedbError::corruption(
                crate::errors::CorruptionDetail::HeaderUnverifiable,
            ));
        }
        let mut segment_id = [0u8; 16];
        segment_id.copy_from_slice(&buf[off..off + 16]);
        off += 16;
        match kind {
            0x01 => actions.push(JournalAction::Promote { segment_id }),
            0x02 => {
                if off + 8 > buf.len() {
                    return Err(PagedbError::corruption(
                        crate::errors::CorruptionDetail::HeaderUnverifiable,
                    ));
                }
                b8.copy_from_slice(&buf[off..off + 8]);
                let tombstone_commit_id = u64::from_le_bytes(b8);
                off += 8;
                actions.push(JournalAction::Tombstone {
                    segment_id,
                    tombstone_commit_id,
                });
            }
            _ => {
                return Err(PagedbError::corruption(
                    crate::errors::CorruptionDetail::HeaderUnverifiable,
                ));
            }
        }
    }

    Ok(ApplyJournalRecord {
        target_commit_id,
        actions,
    })
}

/// Pack a 16-byte journal id into the header's two `apply_journal_root` u64
/// fields (`page_id` = bytes 0..8, `version` = bytes 8..16).
#[must_use]
pub fn encode_journal_id(journal_id: &[u8; 16]) -> (u64, u64) {
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&journal_id[..8]);
    hi.copy_from_slice(&journal_id[8..]);
    (u64::from_le_bytes(lo), u64::from_le_bytes(hi))
}

/// Reconstruct a 16-byte journal id from the header's two `apply_journal_root`
/// u64 fields. An all-zero id means "no apply in flight".
#[must_use]
pub fn decode_journal_id(page_id: u64, version: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&page_id.to_le_bytes());
    id[8..].copy_from_slice(&version.to_le_bytes());
    id
}

/// Read a pending apply-journal sidecar. Returns `Ok(None)` when no journal
/// is in flight (`journal_id == 0`). Action execution is intentionally kept
/// separate so the live `Db` can apply reader-pin policy before deciding
/// whether a tombstone is complete or deferred.
pub async fn replay_apply_journal<V: Vfs + Clone>(
    pager: &crate::pager::Pager<V>,
    realm_id: crate::RealmId,
    journal_id: [u8; 16],
) -> Result<Option<ApplyJournalRecord>> {
    if journal_id == [0u8; 16] {
        return Ok(None);
    }
    let page_size = pager.page_size();
    let cap = body_capacity(page_size);

    // Read page 0 to learn the stream length, then read the remaining pages.
    let first = pager.read_journal_page(journal_id, 0, realm_id).await?;
    let mut stream: Vec<u8> = first.body_ref().to_vec();
    drop(first);

    if stream.len() < STREAM_PREFIX_LEN {
        return Err(PagedbError::corruption(
            crate::errors::CorruptionDetail::HeaderUnverifiable,
        ));
    }
    let mut p4 = [0u8; 4];
    p4.copy_from_slice(&stream[..STREAM_PREFIX_LEN]);
    let stream_len = u32::from_le_bytes(p4) as usize;
    let page_count = page_count_for(stream_len, page_size);

    for page_id in 1..page_count as u64 {
        let guard = pager
            .read_journal_page(journal_id, page_id, realm_id)
            .await?;
        stream.extend_from_slice(guard.body_ref());
        drop(guard);
    }
    debug_assert_eq!(stream.len(), page_count * cap);

    Ok(Some(decode_journal_stream(&stream)?))
}

/// Execute journal actions idempotently when no live reader-pins need to be
/// considered (for example, standalone recovery). Required directory creation,
/// renames, and directory syncs are all fallible. The live `Db` uses its
/// pin-aware reconciliation path instead.
pub async fn execute_journal_actions<V: Vfs>(vfs: &V, actions: &[JournalAction]) -> Result<()> {
    vfs.mkdir_all("seg").await?;
    vfs.mkdir_all("seg/.staging").await?;
    vfs.mkdir_all("seg/.tombstone").await?;
    for action in actions {
        match action {
            JournalAction::Promote { segment_id } => {
                let src = crate::segment::writer::staging_path(segment_id);
                let dst = crate::segment::writer::live_path(segment_id);
                if !path_exists(vfs, &dst).await? {
                    vfs.rename(&src, &dst).await?;
                }
            }
            JournalAction::Tombstone {
                segment_id,
                tombstone_commit_id,
            } => {
                let src = crate::segment::writer::live_path(segment_id);
                let dst = format!(
                    "seg/.tombstone/{}.{}",
                    crate::hex::to_hex_lower(segment_id),
                    tombstone_commit_id,
                );
                if !path_exists(vfs, &dst).await? && path_exists(vfs, &src).await? {
                    vfs.rename(&src, &dst).await?;
                }
            }
        }
    }
    vfs.sync_dir("seg").await?;
    vfs.sync_dir("seg/.staging").await?;
    vfs.sync_dir("seg/.tombstone").await
}

async fn path_exists<V: Vfs>(vfs: &V, path: &str) -> Result<bool> {
    match vfs.open(path, crate::vfs::types::OpenMode::Read).await {
        Ok(_) => Ok(true),
        Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Suppress unused warnings for `PageKind::ApplyJournal` re-export consumers.
const _: PageKind = PageKind::ApplyJournal;

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;

    fn promotes(n: usize) -> ApplyJournalRecord {
        ApplyJournalRecord {
            target_commit_id: 42,
            actions: (0..n)
                .map(|i| JournalAction::Promote {
                    segment_id: [u8::try_from(i % 256).unwrap(); 16],
                })
                .collect(),
        }
    }

    fn round_trip(record: &ApplyJournalRecord) -> ApplyJournalRecord {
        let pages = encode_journal_pages(record, PAGE).unwrap();
        let stream: Vec<u8> = pages.concat();
        decode_journal_stream(&stream).unwrap()
    }

    #[test]
    fn round_trip_single_page() {
        let record = promotes(3);
        assert_eq!(round_trip(&record), record);
    }

    #[test]
    fn round_trip_mixed_actions() {
        let record = ApplyJournalRecord {
            target_commit_id: 101,
            actions: vec![
                JournalAction::Promote {
                    segment_id: [0x01; 16],
                },
                JournalAction::Tombstone {
                    segment_id: [0x02; 16],
                    tombstone_commit_id: 50,
                },
            ],
        };
        assert_eq!(round_trip(&record), record);
    }

    #[test]
    fn round_trip_spans_many_pages() {
        // 5000 promotes far exceed a single page's body capacity — they must
        // span many pages and round-trip without loss.
        let record = promotes(5000);
        let pages = encode_journal_pages(&record, PAGE).unwrap();
        assert!(pages.len() > 1, "5000 promotes must span multiple pages");
        let stream: Vec<u8> = pages.concat();
        assert_eq!(decode_journal_stream(&stream).unwrap(), record);
    }

    #[test]
    fn padding_is_not_decoded_as_actions() {
        // A short record on a full page leaves the tail zero-padded; decode must
        // stop at stream_len and not read padding as a (zero-kind) action.
        let record = promotes(1);
        let pages = encode_journal_pages(&record, PAGE).unwrap();
        assert_eq!(pages.len(), 1);
        let decoded = decode_journal_stream(&pages[0]).unwrap();
        assert_eq!(decoded.actions.len(), 1);
    }

    async fn mk_pager() -> crate::pager::Pager<crate::vfs::memory::MemVfs> {
        let mk = crate::crypto::kdf::derive_mk(&[1u8; 32], &[0u8; 16], 0).unwrap();
        let cfg = crate::pager::PagerConfig {
            page_size: PAGE,
            buffer_pool_pages: 8,
            segment_cache_pages: 8,
            cipher_id: crate::crypto::CipherId::Aes256Gcm,
            mk_epoch: 0,
            main_db_file_id: [0xAB; 16],
            main_db_path: "/main.db".into(),
            anchor_budget: 1_000_000,
            dek_lru_capacity: 32,
            observer_retry_count: 0,
            metrics_enabled: false,
        };
        crate::pager::Pager::open(crate::vfs::memory::MemVfs::new(), mk, cfg)
            .await
            .unwrap()
    }

    /// A journal written through the Pager AEAD path must replay correctly:
    /// the record decodes (no ciphertext-as-plaintext misread), spans every
    /// page it needs, and each promote renames its staging file to live. This
    /// is the crash-mid-apply recovery path.
    #[tokio::test(flavor = "current_thread")]
    async fn replay_promotes_multi_page_set_through_aead() {
        use crate::vfs::{Vfs, VfsFile};
        let pager = mk_pager().await;
        let realm = crate::RealmId([7u8; 16]);
        let journal_id = [0x5Au8; 16];

        // A promotion set far larger than one page.
        let n = 400usize;
        let ids: Vec<[u8; 16]> = (0..n)
            .map(|i| {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                id
            })
            .collect();

        // Stage a file for each id so the promote rename has something to move.
        for id in &ids {
            pager.vfs().mkdir_all("seg/.staging").await.unwrap();
            let p = crate::segment::writer::staging_path(id);
            let mut f = pager
                .vfs()
                .open(&p, crate::vfs::types::OpenMode::CreateOrOpen)
                .await
                .unwrap();
            f.write_at(0, b"seg").await.unwrap();
            f.sync().await.unwrap();
        }

        // Write the journal sidecar via the Pager (AEAD), exactly as apply does.
        let record = ApplyJournalRecord {
            target_commit_id: 9,
            actions: ids
                .iter()
                .map(|&segment_id| JournalAction::Promote { segment_id })
                .collect(),
        };
        let page_bodies = encode_journal_pages(&record, PAGE).unwrap();
        assert!(
            page_bodies.len() > 1,
            "set must span multiple journal pages"
        );
        for (pid, body) in page_bodies.iter().enumerate() {
            pager
                .stage_journal_page(journal_id, pid as u64, realm, body)
                .await
                .unwrap();
        }
        pager.flush_journal(journal_id, realm).await.unwrap();

        // Drop cache pages so replay reads back from disk and must AEAD-decrypt.
        pager.drop_journal_cache(journal_id);

        let replayed = replay_apply_journal(&pager, realm, journal_id)
            .await
            .unwrap()
            .expect("a pending journal must replay");
        assert_eq!(replayed.actions.len(), n);
        execute_journal_actions(pager.vfs(), &replayed.actions)
            .await
            .unwrap();

        // Every staging file is now promoted to its live path.
        for id in &ids {
            let live = crate::segment::writer::live_path(id);
            let staging = crate::segment::writer::staging_path(id);
            assert!(
                pager
                    .vfs()
                    .open(&live, crate::vfs::types::OpenMode::Read)
                    .await
                    .is_ok(),
                "segment not promoted to live path"
            );
            assert!(
                pager
                    .vfs()
                    .open(&staging, crate::vfs::types::OpenMode::Read)
                    .await
                    .is_err(),
                "staging file should be gone after promote"
            );
        }
    }

    #[test]
    fn journal_id_round_trips_through_header_fields() {
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let (pid, ver) = encode_journal_id(&id);
        assert_eq!(decode_journal_id(pid, ver), id);
        assert_eq!(decode_journal_id(0, 0), [0u8; 16]);
    }
}
