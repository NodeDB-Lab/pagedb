//! Open-flow catalog reconciliation. Walks the catalog and matches expected
//! segment files against the live `seg/` and `seg/.staging/` directories.

use std::sync::Arc;

use crate::btree::BTree;
use crate::catalog::codec::SegmentMeta;
use crate::catalog::codec::{Catalog, CatalogRowKind};
use crate::crypto::keys::DerivedKey;
use crate::errors::{CorruptionDetail, PagedbError};
use crate::pager::Pager;
use crate::pager::format::segment_footer::decode_segment_footer;
use crate::pager::format::structural_header::decode_segment_header;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};
use crate::{RealmId, Result};

/// Run open-flow reconciliation. For each catalog entry, probe the expected
/// `seg/<hex(segment_id)>` file. Promote staged files where the live path is
/// missing. Raise corruption on foreign/unverifiable footers or missing files
/// with no recoverable staging. Sweep orphan files into the tombstone
/// directory.
///
/// `db_realm_id` is the Db-level realm used to authenticate the catalog tree
/// pages themselves (not the per-segment realm, which is stored inside each
/// `SegmentMeta`).
#[allow(clippy::too_many_arguments)]
pub async fn reconcile_catalog<V: Vfs + Clone>(
    vfs: &V,
    pager: Arc<Pager<V>>,
    hk: &DerivedKey,
    db_realm_id: RealmId,
    catalog_root_page_id: u64,
    next_page_id: u64,
    page_size: usize,
    parent_file_id: [u8; 16],
    recovery_commit: u64,
) -> Result<Vec<[u8; 16]>> {
    let mut expected: Vec<[u8; 16]> = Vec::new();
    if catalog_root_page_id == 0 {
        sweep_orphans(vfs, &expected, recovery_commit).await?;
        return Ok(expected);
    }
    let tree = BTree::open(
        pager.clone(),
        db_realm_id,
        catalog_root_page_id,
        next_page_id,
        page_size,
    );
    // Bracket all segment rows: prefix 0x01..0x02.
    let start = vec![CatalogRowKind::Segment as u8];
    let mut end = vec![CatalogRowKind::Segment as u8];
    end[0] += 1;
    let rows = tree.collect_range(&start, &end).await?;
    for (key, value) in rows {
        let meta = Catalog::decode_segment_meta(&value)?;
        expected.push(meta.segment_id);
        let live = format!("seg/{}", crate::hex::to_hex_lower(&meta.segment_id));
        let staging = format!(
            "seg/.staging/{}",
            crate::hex::to_hex_lower(&meta.segment_id)
        );
        match vfs.open(&live, OpenMode::Read).await {
            Ok(file) => {
                verify_segment_file::<V>(&file, &meta, hk, &pager, page_size, parent_file_id, &key)
                    .await?;
            }
            Err(PagedbError::Io(_)) => {
                // Missing at live path: look for staging.
                match vfs.open(&staging, OpenMode::Read).await {
                    Ok(file) => {
                        verify_segment_file::<V>(
                            &file,
                            &meta,
                            hk,
                            &pager,
                            page_size,
                            parent_file_id,
                            &key,
                        )
                        .await?;
                        drop(file);
                        vfs.rename(&staging, &live).await?;
                    }
                    Err(_) => {
                        return Err(PagedbError::corruption(CorruptionDetail::SegmentMissing {
                            realm_id: meta.realm_id,
                            name: String::from_utf8_lossy(&key[17..]).into_owned(),
                            segment_id: meta.segment_id,
                        }));
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    vfs.sync_dir("seg").await.ok();
    sweep_orphans(vfs, &expected, recovery_commit).await?;
    Ok(expected)
}

async fn verify_segment_file<V: Vfs + Clone>(
    file: &V::File,
    catalog_meta: &SegmentMeta,
    hk: &DerivedKey,
    pager: &Arc<Pager<V>>,
    page_size: usize,
    parent_file_id: [u8; 16],
    catalog_key: &[u8],
) -> Result<()> {
    let mut header_buf = vec![0u8; page_size];
    file.read_at(0, &mut header_buf).await?;
    let Ok(header_fields) = decode_segment_header(&header_buf, hk, page_size) else {
        return Err(PagedbError::corruption(
            CorruptionDetail::FooterUnverifiable {
                realm_id: catalog_meta.realm_id,
                name: String::from_utf8_lossy(&catalog_key[17..]).into_owned(),
                segment_id: catalog_meta.segment_id,
            },
        ));
    };
    if header_fields.parent_file_id != parent_file_id {
        return Err(PagedbError::corruption(CorruptionDetail::ForeignSegment {
            realm_id: catalog_meta.realm_id,
            name: String::from_utf8_lossy(&catalog_key[17..]).into_owned(),
            segment_id: catalog_meta.segment_id,
            footer_parent_file_id: header_fields.parent_file_id,
            expected_parent_file_id: parent_file_id,
        }));
    }
    let footer_offset = (catalog_meta.page_count - 1)
        .checked_mul(page_size as u64)
        .ok_or_else(|| PagedbError::Io(std::io::Error::other("offset overflow")))?;
    let mut footer_buf = vec![0u8; page_size];
    file.read_at(footer_offset, &mut footer_buf).await?;
    let result = {
        let pager_mk_reconcile = pager.mk();
        let mut lru = pager.dek_lru().lock();
        let cipher = lru.get_or_derive(
            catalog_meta.realm_id,
            catalog_meta.mk_epoch,
            pager.cipher_id(),
            &pager_mk_reconcile,
        )?;
        decode_segment_footer(&footer_buf, hk, cipher, page_size)
    };
    if result.is_err() {
        return Err(PagedbError::corruption(
            CorruptionDetail::FooterUnverifiable {
                realm_id: catalog_meta.realm_id,
                name: String::from_utf8_lossy(&catalog_key[17..]).into_owned(),
                segment_id: catalog_meta.segment_id,
            },
        ));
    }
    Ok(())
}

async fn sweep_orphans<V: Vfs + Clone>(
    vfs: &V,
    expected: &[[u8; 16]],
    recovery_commit: u64,
) -> Result<()> {
    let _ = vfs.mkdir_all("seg/.tombstone").await;
    let Ok(live_entries) = vfs.list_dir("seg").await else {
        return Ok(());
    };
    for name in live_entries {
        if name.starts_with('.') {
            continue;
        }
        let Some(id) = crate::hex::parse_hex::<16>(&name) else {
            continue;
        };
        if !expected.contains(&id) {
            let from = format!("seg/{name}");
            let to = format!("seg/.tombstone/{name}.{recovery_commit}");
            vfs.rename(&from, &to).await.ok();
        }
    }
    let Ok(staging_entries) = vfs.list_dir("seg/.staging").await else {
        return Ok(());
    };
    for name in staging_entries {
        let Some(id) = crate::hex::parse_hex::<16>(&name) else {
            continue;
        };
        if !expected.contains(&id) {
            let path = format!("seg/.staging/{name}");
            vfs.remove(&path).await.ok();
        }
    }
    Ok(())
}
