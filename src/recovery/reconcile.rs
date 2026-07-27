//! Catalog reconciliation at open. Catalog-referenced files are authenticated
//! against their persisted routing metadata before repair or garbage collection.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, CatalogRowKind};
use crate::errors::{CorruptionDetail, PagedbError};
use crate::pager::Pager;
use crate::segment::authenticated_metadata::{
    ExpectedSegmentPath, authenticate_segment_metadata, validate_expected_path,
};
use crate::vfs::Vfs;
use crate::vfs::types::OpenMode;
use crate::{RealmId, Result};

/// Catalog segment rows read per batch while reconciling them at open. A row is
/// a fixed-width authenticated value plus a name capped at
/// `MAX_SEGMENT_NAME_LEN`, so one batch is a few hundred KiB resident no matter
/// how many segments the store has linked.
const SEGMENT_ROW_BATCH: usize = 256;

/// Authenticate catalog-referenced segment files without mutating persistent
/// state. Returns `Unsupported` when completing publication or orphan cleanup
/// would be required.
#[allow(clippy::too_many_arguments)]
pub async fn verify_catalog<V: Vfs + Clone>(
    vfs: &V,
    pager: Arc<Pager<V>>,
    db_realm_id: RealmId,
    catalog_root_page_id: u64,
    next_page_id: u64,
    page_size: usize,
    parent_file_id: [u8; 16],
    _recovery_commit: u64,
) -> Result<Vec<[u8; 16]>> {
    let expected = verify_catalog_entries(
        vfs,
        pager,
        db_realm_id,
        catalog_root_page_id,
        next_page_id,
        page_size,
        parent_file_id,
        false,
    )
    .await?;
    if has_orphans(vfs, &expected).await? {
        return Err(PagedbError::Unsupported);
    }
    Ok(expected)
}

/// Authenticate catalog-referenced segment files, then complete only an
/// authenticated staged publication and sweep catalog-unreferenced files.
#[allow(clippy::too_many_arguments)]
pub async fn repair_catalog<V: Vfs + Clone>(
    vfs: &V,
    pager: Arc<Pager<V>>,
    db_realm_id: RealmId,
    catalog_root_page_id: u64,
    next_page_id: u64,
    page_size: usize,
    parent_file_id: [u8; 16],
    recovery_commit: u64,
) -> Result<Vec<[u8; 16]>> {
    let expected = verify_catalog_entries(
        vfs,
        pager,
        db_realm_id,
        catalog_root_page_id,
        next_page_id,
        page_size,
        parent_file_id,
        true,
    )
    .await?;
    sweep_orphans(vfs, &expected, recovery_commit).await?;
    Ok(expected)
}

#[allow(clippy::too_many_arguments)]
async fn verify_catalog_entries<V: Vfs + Clone>(
    vfs: &V,
    pager: Arc<Pager<V>>,
    db_realm_id: RealmId,
    catalog_root_page_id: u64,
    next_page_id: u64,
    page_size: usize,
    parent_file_id: [u8; 16],
    repair: bool,
) -> Result<Vec<[u8; 16]>> {
    if catalog_root_page_id == 0 {
        return Ok(Vec::new());
    }
    let tree = BTree::open(
        pager.clone(),
        db_realm_id,
        catalog_root_page_id,
        next_page_id,
        page_size,
    );

    // Rows are streamed in bounded batches: how many segments an embedder has
    // linked is its business, and open must not size an allocation by it. What
    // survives the walk is one 16-byte identity per catalog row, which the
    // orphan reconciliation below genuinely needs to classify the files on
    // disk, plus the still-staged files a crash left mid-publication — transient
    // publication state, not a function of how much is stored.
    //
    // Every persistent mutation — promotion here, the caller's orphan sweep —
    // still happens only after the whole catalog has streamed and validated, so
    // a malformed row anywhere aborts before anything on disk moves. Opening and
    // authenticating a file inside the walk changes nothing on disk.
    let prefix = [CatalogRowKind::Segment as u8];
    let mut cursor: Vec<u8> = prefix.to_vec();
    let mut expected: Vec<[u8; 16]> = Vec::new();
    let mut staged_promotions = Vec::new();
    loop {
        let batch = tree
            .collect_prefix_batch_from(&prefix, &cursor, SEGMENT_ROW_BATCH)
            .await?;
        let Some((last_key, _)) = batch.last() else {
            break;
        };
        cursor.clear();
        cursor.extend_from_slice(last_key);
        // The exact successor of `last_key` in the key ordering: resume strictly
        // past the row just reconciled without re-reading it.
        cursor.push(0);
        let exhausted = batch.len() < SEGMENT_ROW_BATCH;

        for (key, value) in &batch {
            let (segment_id, promotion) =
                authenticate_row(vfs, &pager, key, value, parent_file_id, page_size).await?;
            expected.push(segment_id);
            if let Some(promotion) = promotion {
                staged_promotions.push(promotion);
            }
        }

        if exhausted {
            break;
        }
    }

    if !staged_promotions.is_empty() && !repair {
        return Err(PagedbError::Unsupported);
    }
    for (staging, live) in staged_promotions {
        vfs.rename(&staging, &live).await?;
        vfs.sync_dir("seg").await?;
    }
    Ok(expected)
}

/// Validate one catalog segment row and authenticate the file it names against
/// its persisted routing metadata.
///
/// Returns the row's segment identity and, when the live file is absent but an
/// authenticated staged one exists, the `(staging, live)` rename that would
/// complete its publication. Nothing on disk is mutated here — the caller
/// applies promotions only once the whole catalog has streamed and validated.
async fn authenticate_row<V: Vfs + Clone>(
    vfs: &V,
    pager: &Arc<Pager<V>>,
    key: &[u8],
    value: &[u8],
    parent_file_id: [u8; 16],
    page_size: usize,
) -> Result<([u8; 16], Option<(String, String)>)> {
    let meta = Catalog::decode_segment_meta(value)?;
    let name = Catalog::validate_segment_key(key, &meta)?;

    let live = format!("seg/{}", crate::hex::to_hex_lower(&meta.segment_id));
    match vfs.open(&live, OpenMode::Read).await {
        Ok(file) => {
            validate_expected_path(&meta, &live, ExpectedSegmentPath::Live)?;
            authenticate_segment_metadata(pager, &file, &meta, parent_file_id, page_size).await?;
            Ok((meta.segment_id, None))
        }
        Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let staging = format!(
                "seg/.staging/{}",
                crate::hex::to_hex_lower(&meta.segment_id)
            );
            let file = match vfs.open(&staging, OpenMode::Read).await {
                Ok(file) => file,
                Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(PagedbError::corruption(CorruptionDetail::SegmentMissing {
                        realm_id: meta.realm_id,
                        name: String::from_utf8_lossy(name).into_owned(),
                        segment_id: meta.segment_id,
                    }));
                }
                Err(error) => return Err(error),
            };
            validate_expected_path(&meta, &staging, ExpectedSegmentPath::Staging)?;
            authenticate_segment_metadata(pager, &file, &meta, parent_file_id, page_size).await?;
            drop(file);
            Ok((meta.segment_id, Some((staging, live))))
        }
        Err(error) => Err(error),
    }
}

async fn has_orphans<V: Vfs>(vfs: &V, expected: &[[u8; 16]]) -> Result<bool> {
    let expected_ids: BTreeSet<[u8; 16]> = expected.iter().copied().collect();
    let live_entries = vfs.list_dir("seg").await?;
    for name in live_entries {
        if name.starts_with('.') {
            continue;
        }
        let Some(id) = crate::hex::parse_hex::<16>(&name) else {
            continue;
        };
        if !expected_ids.contains(&id) {
            return Ok(true);
        }
    }
    let staging_entries = vfs.list_dir("seg/.staging").await?;
    for name in staging_entries {
        let Some(id) = crate::hex::parse_hex::<16>(&name) else {
            continue;
        };
        if !expected_ids.contains(&id) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn sweep_orphans<V: Vfs>(vfs: &V, expected: &[[u8; 16]], recovery_commit: u64) -> Result<()> {
    let expected_ids: BTreeSet<[u8; 16]> = expected.iter().copied().collect();
    vfs.mkdir_all("seg/.tombstone").await?;
    let live_entries = vfs.list_dir("seg").await?;
    for name in live_entries {
        if name.starts_with('.') {
            continue;
        }
        let Some(id) = crate::hex::parse_hex::<16>(&name) else {
            continue;
        };
        if !expected_ids.contains(&id) {
            let from = format!("seg/{name}");
            let to = format!("seg/.tombstone/{name}.{recovery_commit}");
            vfs.rename(&from, &to).await?;
        }
    }
    let staging_entries = vfs.list_dir("seg/.staging").await?;
    for name in staging_entries {
        let Some(id) = crate::hex::parse_hex::<16>(&name) else {
            continue;
        };
        if !expected_ids.contains(&id) {
            vfs.remove(&format!("seg/.staging/{name}")).await?;
        }
    }
    vfs.sync_dir("seg").await?;
    vfs.sync_dir("seg/.tombstone").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::catalog::codec::{Catalog, SegmentKind, SegmentMeta};
    use crate::crypto::CipherId;
    use crate::crypto::kdf::derive_mk;
    use crate::errors::{CorruptionDetail, Evictable, PagedbError};
    use crate::pager::Pager;
    use crate::pager::core::PagerConfig;
    use crate::vfs::memory::MemVfs;
    use crate::vfs::types::OpenMode;
    use crate::vfs::{Vfs, VfsFile};
    use crate::{RealmId, btree::BTree};

    use super::{repair_catalog, sweep_orphans};

    fn segment_id(value: u64) -> [u8; 16] {
        let mut id = [0; 16];
        id[..8].copy_from_slice(&value.to_le_bytes());
        id
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_catalog_key_prevents_reconciliation_mutation() {
        const PAGE_SIZE: usize = 4096;
        let realm = RealmId([0xA1; 16]);
        let parent_file_id = [0xB2; 16];
        let vfs = MemVfs::new();
        let master = derive_mk(&[0xC3; 32], &[0; 16], 0).unwrap();
        let pager = Arc::new(
            Pager::open(
                vfs.clone(),
                master,
                PagerConfig::with_defaults(
                    PAGE_SIZE,
                    CipherId::Aes256Gcm,
                    0,
                    parent_file_id,
                    "main.db",
                ),
            )
            .await
            .unwrap(),
        );
        let meta = SegmentMeta {
            segment_id: [0xD4; 16],
            segment_kind: SegmentKind::Unspecified,
            realm_id: realm,
            parent_file_id,
            linked_commit: None,
            page_count: 2,
            total_bytes: u64::try_from(PAGE_SIZE * 2).unwrap(),
            final_counter: 0,
            mk_epoch: 0,
            cipher_id: CipherId::Aes256Gcm.as_byte(),
            format_version: 1,
            evictable: Evictable::Authoritative,
        };
        let mut tree = BTree::open(pager.clone(), realm, 0, 4, PAGE_SIZE);
        tree.put(&[0x01], &Catalog::encode_segment_meta(&meta))
            .await
            .unwrap();
        tree.flush().await.unwrap();

        vfs.mkdir_all("seg/.staging").await.unwrap();
        let marker = "seg/.staging/unrelated";
        let mut marker_file = vfs.open(marker, OpenMode::CreateNew).await.unwrap();
        marker_file.write_at(0, b"keep").await.unwrap();
        drop(marker_file);

        let error = repair_catalog(
            &vfs,
            pager,
            realm,
            tree.root_page_id(),
            tree.next_page_id(),
            PAGE_SIZE,
            parent_file_id,
            1,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            PagedbError::Corruption(CorruptionDetail::CatalogRowInvalid {
                field: "segment.key.length"
            })
        ));
        assert!(vfs.open(marker, OpenMode::Read).await.is_ok());
    }

    /// The sweep has three outcomes and every one of them is destructive if it
    /// fires on the wrong file: an expected live segment must survive, a live
    /// segment the catalog does not name must become a tombstone rather than a
    /// deletion, and an unnamed staging file must be removed outright. The
    /// expected set is large enough that a membership test which silently
    /// matched on a prefix, a truncated id, or the first entry alone would
    /// misclassify one of the three.
    #[tokio::test(flavor = "current_thread")]
    async fn sweep_orphans_tombstones_live_orphans_and_removes_staged_orphans() {
        let vfs = MemVfs::new();
        vfs.mkdir_all("seg/.staging").await.unwrap();
        let expected: Vec<[u8; 16]> = (0..1024).map(segment_id).collect();

        for id in expected.iter().take(8) {
            let path = crate::segment::writer::live_path(id);
            let mut file = vfs.open(&path, OpenMode::CreateOrOpen).await.unwrap();
            file.write_at(0, b"live").await.unwrap();
        }

        let live_orphan = segment_id(10_000);
        let live_orphan_path = crate::segment::writer::live_path(&live_orphan);
        let mut live_file = vfs
            .open(&live_orphan_path, OpenMode::CreateOrOpen)
            .await
            .unwrap();
        live_file.write_at(0, b"orphan").await.unwrap();

        let staged_orphan = segment_id(10_001);
        let staged_orphan_path = crate::segment::writer::staging_path(&staged_orphan);
        let mut staged_file = vfs
            .open(&staged_orphan_path, OpenMode::CreateOrOpen)
            .await
            .unwrap();
        staged_file.write_at(0, b"orphan").await.unwrap();

        sweep_orphans(&vfs, &expected, 77).await.unwrap();

        for id in expected.iter().take(8) {
            let path = crate::segment::writer::live_path(id);
            assert!(
                vfs.open(&path, OpenMode::Read).await.is_ok(),
                "a segment the catalog names must survive the sweep: {path}"
            );
        }
        assert!(vfs.open(&live_orphan_path, OpenMode::Read).await.is_err());
        let tombstone = format!(
            "seg/.tombstone/{}.77",
            crate::hex::to_hex_lower(&live_orphan)
        );
        assert!(vfs.open(&tombstone, OpenMode::Read).await.is_ok());
        assert!(vfs.open(&staged_orphan_path, OpenMode::Read).await.is_err());
    }
}
