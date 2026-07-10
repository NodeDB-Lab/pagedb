use std::sync::Arc;

use crate::RealmId;
use crate::catalog::codec::{SegmentKind, SegmentMeta};
use crate::crypto::CipherId;
use crate::crypto::aad::{Aad, AadFields};
use crate::crypto::kdf::{derive_dek, derive_hk, derive_mk};
use crate::crypto::nonce::Nonce;
use crate::errors::{CorruptionDetail, PagedbError};
use crate::pager::Pager;
use crate::pager::core::PagerConfig;
use crate::pager::format::data_page::{body_mut, open_data_page, seal_data_page};
use crate::pager::format::page_kind::PageKind;
use crate::pager::format::segment_footer::{decode_segment_footer, encode_segment_footer};
use crate::vfs::memory::MemVfs;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};

use super::{ExpectedSegmentPath, authenticate_segment_metadata, validate_expected_path};
use crate::segment::writer::{SegmentWriter, live_path, staging_path};

const PAGE_SIZE: usize = 4096;
const REALM: RealmId = RealmId([0xA5; 16]);
const FILE_ID: [u8; 16] = [0xB6; 16];
const KEK: [u8; 32] = [0xC7; 32];

async fn sealed_fixture() -> (Arc<Pager<MemVfs>>, MemVfs, SegmentMeta) {
    let vfs = MemVfs::new();
    let master = derive_mk(&KEK, &[0; 16], 0).unwrap();
    let config = PagerConfig::with_defaults(PAGE_SIZE, CipherId::Aes256Gcm, 0, FILE_ID, "main.db");
    let pager = Arc::new(Pager::open(vfs.clone(), master, config).await.unwrap());
    let segment_id = [0xD8; 16];
    let mut writer = SegmentWriter::create_internal(
        pager.clone(),
        REALM,
        segment_id,
        FILE_ID,
        SegmentKind::Unspecified,
    )
    .await
    .unwrap();
    writer
        .append_page(crate::segment::types::SegmentPageKind::Data, b"payload")
        .await
        .unwrap();
    let meta = writer.seal().await.unwrap();
    vfs.rename(&staging_path(&segment_id), &live_path(&segment_id))
        .await
        .unwrap();
    (pager, vfs, meta)
}

async fn indexed_fixture() -> (Arc<Pager<MemVfs>>, MemVfs, SegmentMeta) {
    let vfs = MemVfs::new();
    let master = derive_mk(&KEK, &[0; 16], 0).unwrap();
    let config = PagerConfig::with_defaults(PAGE_SIZE, CipherId::Aes256Gcm, 0, FILE_ID, "main.db");
    let pager = Arc::new(Pager::open(vfs.clone(), master, config).await.unwrap());
    let segment_id = [0xD9; 16];
    let mut writer = SegmentWriter::create_internal(
        pager.clone(),
        REALM,
        segment_id,
        FILE_ID,
        SegmentKind::Unspecified,
    )
    .await
    .unwrap();
    writer.append_extent(&[b"first"]).await.unwrap();
    writer.append_extent(&[b"second"]).await.unwrap();
    let meta = writer.seal().await.unwrap();
    vfs.rename(&staging_path(&segment_id), &live_path(&segment_id))
        .await
        .unwrap();
    (pager, vfs, meta)
}

async fn rewrite_first_index_page(
    vfs: &MemVfs,
    meta: &SegmentMeta,
    rewrite: impl FnOnce(&mut [u8]),
) {
    let page_id = meta.page_count - 2;
    let offset = page_id * u64::try_from(PAGE_SIZE).unwrap();
    let path = live_path(&meta.segment_id);
    let mut file = vfs.open(&path, OpenMode::ReadWrite).await.unwrap();
    let mut page = vec![0u8; PAGE_SIZE];
    file.read_at(offset, &mut page).await.unwrap();
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&page[12..24]);
    let master = derive_mk(&KEK, &[0; 16], 0).unwrap();
    let dek = derive_dek(&master, REALM).unwrap();
    let cipher = crate::crypto::Cipher::new_aes_gcm(&dek);
    let aad = Aad::from_fields(AadFields {
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        page_kind: PageKind::SegmentIndex.as_byte(),
        mk_epoch: 0,
        page_id,
        realm_id: REALM,
        segment_id: meta.segment_id,
    });
    open_data_page(&mut page, &aad, &cipher).unwrap();
    rewrite(body_mut(&mut page));
    seal_data_page(
        &mut page,
        PageKind::SegmentIndex,
        0,
        0,
        &Nonce::from_bytes(nonce_bytes),
        &aad,
        &cipher,
    )
    .unwrap();
    file.write_at(offset, &page).await.unwrap();
}

fn is_mismatch<T>(result: &crate::Result<T>, field: &'static str) {
    assert!(matches!(
        result,
        Err(PagedbError::Corruption(CorruptionDetail::SegmentMetadataMismatch { field: actual })) if *actual == field
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_authenticated_header_metadata_disagreement() {
    let (pager, vfs, mut meta) = sealed_fixture().await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    meta.segment_id = [0xE9; 16];
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "header.segment_id",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_authenticated_footer_format_disagreement() {
    let (pager, vfs, mut meta) = sealed_fixture().await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    meta.format_version = 1;
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "footer.format_version",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_authenticated_footer_metadata_disagreement() {
    let (pager, vfs, mut meta) = sealed_fixture().await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    meta.final_counter = meta.final_counter.checked_add(1).unwrap();
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "footer.final_counter",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_inconsistent_catalog_geometry_before_footer_read() {
    let (pager, vfs, mut meta) = sealed_fixture().await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    meta.total_bytes = meta.total_bytes.checked_add(1).unwrap();
    assert!(matches!(
        authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        Err(PagedbError::Corruption(
            CorruptionDetail::SegmentGeometryInvalid {
                field: "total_bytes"
            }
        ))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_invalid_v2_index_range_after_footer_authentication() {
    let (pager, vfs, meta) = sealed_fixture().await;
    let path = live_path(&meta.segment_id);
    let mut file = vfs.open(&path, OpenMode::ReadWrite).await.unwrap();
    let footer_offset = (meta.page_count - 1)
        .checked_mul(u64::try_from(PAGE_SIZE).unwrap())
        .unwrap();
    let mut footer = vec![0; PAGE_SIZE];
    file.read_at(footer_offset, &mut footer).await.unwrap();
    let master = derive_mk(&KEK, &[0; 16], 0).unwrap();
    let hk = derive_hk(&master).unwrap();
    let dek = derive_dek(&master, REALM).unwrap();
    let cipher = crate::crypto::Cipher::new_aes_gcm(&dek);
    let (mut fields, manifest) = decode_segment_footer(&footer, &hk, &cipher, PAGE_SIZE).unwrap();
    fields.index_start_page = meta.page_count - 1;
    fields.index_page_count = 1;
    let replacement = encode_segment_footer(&fields, &manifest, &hk, &cipher, PAGE_SIZE).unwrap();
    file.write_at(footer_offset, &replacement).await.unwrap();
    drop(file);
    let file = vfs.open(&path, OpenMode::Read).await.unwrap();
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "footer.index",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_v2_index_gap() {
    let (pager, vfs, meta) = indexed_fixture().await;
    let path = live_path(&meta.segment_id);
    let footer_offset = (meta.page_count - 1) * u64::try_from(PAGE_SIZE).unwrap();
    let mut file = vfs.open(&path, OpenMode::ReadWrite).await.unwrap();
    let mut footer = vec![0; PAGE_SIZE];
    file.read_at(footer_offset, &mut footer).await.unwrap();
    let master = derive_mk(&KEK, &[0; 16], 0).unwrap();
    let hk = derive_hk(&master).unwrap();
    let dek = derive_dek(&master, REALM).unwrap();
    let cipher = crate::crypto::Cipher::new_aes_gcm(&dek);
    let (mut fields, manifest) = decode_segment_footer(&footer, &hk, &cipher, PAGE_SIZE).unwrap();
    fields.index_start_page = 1;
    fields.index_page_count = 1;
    let replacement = encode_segment_footer(&fields, &manifest, &hk, &cipher, PAGE_SIZE).unwrap();
    file.write_at(footer_offset, &replacement).await.unwrap();
    drop(file);
    let file = vfs.open(&path, OpenMode::Read).await.unwrap();
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "footer.index",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_zero_extent_index_entry() {
    let (pager, vfs, meta) = indexed_fixture().await;
    rewrite_first_index_page(&vfs, &meta, |body| body[8..12].fill(0)).await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "index.entry.zero",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_overlapping_extent_index_entries() {
    let (pager, vfs, meta) = indexed_fixture().await;
    rewrite_first_index_page(&vfs, &meta, |body| {
        body[32..40].copy_from_slice(&1u64.to_le_bytes());
    })
    .await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "index.entry.order",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_out_of_order_extent_index_entries() {
    let (pager, vfs, meta) = indexed_fixture().await;
    rewrite_first_index_page(&vfs, &meta, |body| {
        body[0..8].copy_from_slice(&2u64.to_le_bytes());
        body[32..40].copy_from_slice(&1u64.to_le_bytes());
    })
    .await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "index.entry.order",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_out_of_range_extent_index_entry() {
    let (pager, vfs, meta) = indexed_fixture().await;
    let index_start_page = meta.page_count - 2;
    rewrite_first_index_page(&vfs, &meta, |body| {
        body[0..8].copy_from_slice(&index_start_page.to_le_bytes());
    })
    .await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "index.entry.range",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_final_counter_that_matches_catalog_but_not_geometry() {
    let (pager, vfs, mut meta) = sealed_fixture().await;
    let path = live_path(&meta.segment_id);
    let footer_offset = (meta.page_count - 1) * u64::try_from(PAGE_SIZE).unwrap();
    let mut file = vfs.open(&path, OpenMode::ReadWrite).await.unwrap();
    let mut footer = vec![0; PAGE_SIZE];
    file.read_at(footer_offset, &mut footer).await.unwrap();
    let master = derive_mk(&KEK, &[0; 16], 0).unwrap();
    let hk = derive_hk(&master).unwrap();
    let dek = derive_dek(&master, REALM).unwrap();
    let cipher = crate::crypto::Cipher::new_aes_gcm(&dek);
    let (mut fields, manifest) = decode_segment_footer(&footer, &hk, &cipher, PAGE_SIZE).unwrap();
    fields.final_counter = fields.final_counter.checked_add(1).unwrap();
    meta.final_counter = fields.final_counter;
    let replacement = encode_segment_footer(&fields, &manifest, &hk, &cipher, PAGE_SIZE).unwrap();
    file.write_at(footer_offset, &replacement).await.unwrap();
    drop(file);
    let file = vfs.open(&path, OpenMode::Read).await.unwrap();
    is_mismatch(
        &authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        "footer.final_counter_geometry",
    );
}

#[test]
fn rejects_non_identity_keyed_reconciliation_path() {
    let meta = SegmentMeta {
        segment_id: [1; 16],
        segment_kind: SegmentKind::Unspecified,
        realm_id: REALM,
        parent_file_id: FILE_ID,
        linked_commit: None,
        page_count: 2,
        total_bytes: u64::try_from(PAGE_SIZE * 2).unwrap(),
        final_counter: 0,
        mk_epoch: 0,
        cipher_id: CipherId::Aes256Gcm.as_byte(),
        format_version: 2,
        evictable: crate::errors::Evictable::Authoritative,
    };
    is_mismatch(
        &validate_expected_path(&meta, "seg/not-the-segment-id", ExpectedSegmentPath::Live),
        "path",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mixed_cipher_segments_use_their_persisted_routing_tuples() {
    let vfs = MemVfs::new();
    let old_master = derive_mk(&KEK, &[0; 16], 0).unwrap();
    let old_pager = Arc::new(
        Pager::open(
            vfs.clone(),
            old_master,
            PagerConfig::with_defaults(PAGE_SIZE, CipherId::Aes256Gcm, 0, FILE_ID, "main.db"),
        )
        .await
        .unwrap(),
    );
    let mut old_writer = SegmentWriter::create_internal(
        old_pager,
        REALM,
        [0xE1; 16],
        FILE_ID,
        SegmentKind::Unspecified,
    )
    .await
    .unwrap();
    old_writer
        .append_page(crate::segment::types::SegmentPageKind::Data, b"old")
        .await
        .unwrap();
    let old_meta = old_writer.seal().await.unwrap();
    vfs.rename(
        &staging_path(&old_meta.segment_id),
        &live_path(&old_meta.segment_id),
    )
    .await
    .unwrap();

    let current_master = derive_mk(&[0xF2; 32], &[0; 16], 1).unwrap();
    let current = Arc::new(
        Pager::open(
            vfs.clone(),
            current_master,
            PagerConfig::with_defaults(
                PAGE_SIZE,
                CipherId::ChaCha20Poly1305,
                1,
                FILE_ID,
                "main.db",
            ),
        )
        .await
        .unwrap(),
    );
    let retained_old_master = derive_mk(&KEK, &[0; 16], 0).unwrap();
    current.install_mk_epoch(retained_old_master, 0, CipherId::Aes256Gcm);
    let mut current_writer = SegmentWriter::create_internal(
        current.clone(),
        REALM,
        [0xE2; 16],
        FILE_ID,
        SegmentKind::Unspecified,
    )
    .await
    .unwrap();
    current_writer
        .append_page(crate::segment::types::SegmentPageKind::Data, b"current")
        .await
        .unwrap();
    let current_meta = current_writer.seal().await.unwrap();
    vfs.rename(
        &staging_path(&current_meta.segment_id),
        &live_path(&current_meta.segment_id),
    )
    .await
    .unwrap();

    let old_file = vfs
        .open(&live_path(&old_meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    let current_file = vfs
        .open(&live_path(&current_meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    assert!(
        authenticate_segment_metadata(&current, &old_file, &old_meta, FILE_ID, PAGE_SIZE)
            .await
            .is_ok()
    );
    assert!(
        authenticate_segment_metadata(&current, &current_file, &current_meta, FILE_ID, PAGE_SIZE,)
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn old_epoch_segment_uses_its_persisted_key_after_activation_changes() {
    let (pager, vfs, meta) = sealed_fixture().await;
    let next_master = derive_mk(&[0xDD; 32], &[0; 16], 1).unwrap();
    pager.set_active_mk_epoch(next_master, 1);
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    assert!(
        authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE)
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn missing_persisted_epoch_key_has_deterministic_error() {
    let (pager, vfs, mut meta) = sealed_fixture().await;
    let file = vfs
        .open(&live_path(&meta.segment_id), OpenMode::Read)
        .await
        .unwrap();
    meta.mk_epoch = 77;
    assert!(matches!(
        authenticate_segment_metadata(&pager, &file, &meta, FILE_ID, PAGE_SIZE).await,
        Err(PagedbError::MissingPersistedKey {
            mk_epoch: 77,
            cipher_id: 1
        })
    ));
}
