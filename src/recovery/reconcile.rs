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
    let start = vec![CatalogRowKind::Segment as u8];
    let mut end = start.clone();
    end[0] = end[0]
        .checked_add(1)
        .ok_or_else(|| PagedbError::arithmetic_overflow("catalog segment range"))?;
    let rows = tree.collect_range(&start, &end).await?;
    let mut expected = Vec::with_capacity(rows.len());
    let mut catalog_entries = Vec::with_capacity(rows.len());

    // Validate every authenticated catalog key/value pair before touching the
    // filesystem. In particular, repair must never promote or sweep a file
    // when a later row is malformed.
    for (key, value) in rows {
        let meta = Catalog::decode_segment_meta(&value)?;
        let name = Catalog::validate_segment_key(&key, &meta)?;
        expected.push(meta.segment_id);
        catalog_entries.push((meta, String::from_utf8_lossy(name).into_owned()));
    }

    let mut staged_promotions = Vec::new();
    for (meta, name) in &catalog_entries {
        let live = format!("seg/{}", crate::hex::to_hex_lower(&meta.segment_id));
        match vfs.open(&live, OpenMode::Read).await {
            Ok(file) => {
                validate_expected_path(meta, &live, ExpectedSegmentPath::Live)?;
                authenticate_segment_metadata(&pager, &file, meta, parent_file_id, page_size)
                    .await?;
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
                            name: name.clone(),
                            segment_id: meta.segment_id,
                        }));
                    }
                    Err(error) => return Err(error),
                };
                validate_expected_path(meta, &staging, ExpectedSegmentPath::Staging)?;
                authenticate_segment_metadata(&pager, &file, meta, parent_file_id, page_size)
                    .await?;
                drop(file);
                staged_promotions.push((staging, live));
            }
            Err(error) => return Err(error),
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

    use super::repair_catalog;

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
            format_version: 2,
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
}
