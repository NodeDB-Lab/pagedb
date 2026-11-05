//! A torn free-list chain page must not stop the open that resumes a rekey.
//!
//! The open detaches the chain before the resume reads it. The physical sweep in
//! the deep walk still reports abandoned pages it cannot authenticate, until a
//! compaction rebuilds the file. So these tests hold every page issue to the
//! abandoned set, and require a clean walk after the compaction.

use std::collections::BTreeSet;

use crate::catalog::codec::{RekeyIntent, RekeyStage};
use crate::options::RetainPolicy;
use crate::pager::freelist::read_chain;
use crate::txn::db::core::RekeyTestFault;
use crate::txn::db::rekey::intent::intent_proof;
use crate::vfs::memory::MemVfs;
use crate::vfs::{OpenMode, Vfs, VfsFile};
use crate::{Db, OpenOptions};

use super::{KEK0, PAGE, REALM, store_with_a_free_page};

/// One overwrite frees one overflow page per row, which fills more than one chain page.
const ROWS: u32 = 400;
/// A value past the inline threshold that fits in one overflow page.
const VALUE_LEN: usize = 3000;
const GARBLED_LEN: usize = 32;

#[derive(Clone, Copy, Debug)]
enum Tear {
    /// The kind byte survives and the tag fails.
    TailHalf,
    /// The envelope no longer names a cipher.
    GarbledFirstBytes,
}

fn options() -> OpenOptions {
    OpenOptions::default().with_commit_history_retain(RetainPolicy::Disabled)
}

fn row_key(row: u32) -> Vec<u8> {
    format!("row-{row:05}").into_bytes()
}

fn row_value(row: u32, generation: u8) -> Vec<u8> {
    let mut value = vec![generation; VALUE_LEN];
    value[..4].copy_from_slice(&row.to_le_bytes());
    value
}

async fn overwrite_every_row(db: &Db<MemVfs>, generation: u8) {
    let mut txn = db.begin_write().await.unwrap();
    for row in 0..ROWS {
        txn.put(&row_key(row), &row_value(row, generation))
            .await
            .unwrap();
    }
    txn.commit().await.unwrap();
}

async fn tear(vfs: &MemVfs, page_id: u64, shape: Tear) {
    let offset = page_id * PAGE as u64;
    let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    match shape {
        Tear::TailHalf => {
            file.write_at(offset + (PAGE / 2) as u64, &[0xEE; PAGE / 2])
                .await
                .unwrap();
        }
        Tear::GarbledFirstBytes => {
            file.write_at(offset, &[0xEE; GARBLED_LEN]).await.unwrap();
        }
    }
    file.sync().await.unwrap();
}

/// A store whose rekey stopped at `point`, with the chain its durable header names.
/// Returns the chain's own pages, and those pages plus every page the chain names.
async fn interrupted_store(point: RekeyTestFault) -> (MemVfs, Vec<u64>, BTreeSet<u64>) {
    let vfs = MemVfs::new();
    let db = Db::open_internal_with_options(vfs.clone(), KEK0, PAGE, REALM, options())
        .await
        .unwrap();
    overwrite_every_row(&db, 0).await;
    overwrite_every_row(&db, 1).await;

    db.interrupt_rekey_after(point);
    assert!(db.rekey_db(KEK0, 1).await.is_err(), "{point:?}");

    let head = db.writer.lock().await.free_list_root_page_id;
    let (entries, chain_pages) = read_chain(&db.pager, REALM, head).await.unwrap();
    assert!(
        chain_pages.len() >= 2,
        "setup error: {point:?} leaves a chain of {} pages, so no page has a later link",
        chain_pages.len()
    );
    let mut abandoned: BTreeSet<u64> = chain_pages.iter().copied().collect();
    abandoned.extend(entries.iter().map(|&(_, page_id)| page_id));
    drop(db);
    (vfs, chain_pages, abandoned)
}

async fn assert_settled_past_tear(db: &Db<MemVfs>, abandoned: &BTreeSet<u64>, label: &str) {
    {
        let state = db.writer.lock().await;
        assert!(
            db.load_rekey_intent(&state).await.unwrap().is_none(),
            "{label}: the resumed rekey clears its durable intent"
        );
    }
    {
        let reader = db.begin_read().await.unwrap();
        for row in [0, ROWS - 1] {
            assert_eq!(
                reader.get(&row_key(row)).await.unwrap().as_deref(),
                Some(row_value(row, 1).as_slice()),
                "{label}: row {row}"
            );
        }
    }

    let report = crate::recovery::deep_walk::run_deep_walk(db).await.unwrap();
    let outside: Vec<_> = report
        .page_issues
        .iter()
        .filter(|issue| !abandoned.contains(&issue.page_id))
        .collect();
    assert!(
        outside.is_empty(),
        "{label}: a page issue outside the abandoned set: {outside:?}"
    );

    db.compact_now().await.unwrap();
    let report = crate::recovery::deep_walk::run_deep_walk(db).await.unwrap();
    assert!(report.is_clean(), "{label}: deep walk report: {report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn resume_opens_past_any_torn_chain_page_at_every_stage_and_tear_shape() {
    let stages = [
        RekeyTestFault::Intent,
        RekeyTestFault::MainPagesTargetReadable,
        RekeyTestFault::HeaderTargetPublished,
    ];
    for point in stages {
        for shape in [Tear::TailHalf, Tear::GarbledFirstBytes] {
            let mut index = 0;
            loop {
                let (vfs, chain_pages, abandoned) = interrupted_store(point).await;
                tear(&vfs, chain_pages[index], shape).await;
                let label = format!("{point:?} {shape:?} chain page {index}");
                let db = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options())
                    .await
                    .unwrap_or_else(|error| panic!("{label}: the resume failed: {error:?}"));
                assert_settled_past_tear(&db, &abandoned, &label).await;
                index += 1;
                if index == chain_pages.len() {
                    break;
                }
            }
        }
    }
}

/// A store holding an intent row from an earlier release, whose target proof is
/// zeros, with its chain head torn.
async fn torn_chain_under_a_legacy_intent() -> MemVfs {
    let (vfs, db, _free_pages) = store_with_a_free_page(options()).await;
    let cipher_id = db.cipher_id.as_byte();
    let source_header_key = db.hk.read().clone();
    let source_hk_proof = intent_proof(
        &source_header_key,
        &db.file_id,
        &db.kek_salt,
        0,
        1,
        0,
        cipher_id,
    )
    .unwrap();
    let intent = RekeyIntent {
        source_mk_epoch: 0,
        target_mk_epoch: 1,
        source_cipher_id: cipher_id,
        target_cipher_id: cipher_id,
        same_kek: true,
        stage: RekeyStage::Intent,
        source_hk_proof,
        target_hk_proof: [0; 16],
    };
    let head = {
        let mut state = db.writer.lock().await;
        db.write_rekey_intent_locked(&mut state, &intent, 0, &source_header_key)
            .await
            .unwrap();
        state.free_list_root_page_id
    };
    db.pager.flush_main(REALM).await.unwrap();
    let (_entries, chain_pages) = read_chain(&db.pager, REALM, head).await.unwrap();
    drop(db);
    tear(&vfs, chain_pages[0], Tear::TailHalf).await;
    vfs
}

/// Persisting the proof folds the free list, so the fold must follow the detach.
#[tokio::test(flavor = "current_thread")]
async fn resume_of_a_legacy_intent_opens_past_a_torn_chain_page() {
    let vfs = torn_chain_under_a_legacy_intent().await;
    let db = Db::open_existing_with_options(vfs, KEK0, PAGE, REALM, options())
        .await
        .expect("the proof write follows the detach, so the open succeeds");
    {
        let state = db.writer.lock().await;
        assert!(
            db.load_rekey_intent(&state).await.unwrap().is_none(),
            "the resumed rekey clears its durable intent"
        );
    }
    let reader = db.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"kept").await.unwrap().as_deref(),
        Some(b"second".as_slice())
    );
}

/// A handle without recovery authority refuses the resume, and writes no proof.
#[tokio::test(flavor = "current_thread")]
async fn read_only_open_of_a_legacy_intent_leaves_the_headers_unchanged() {
    async fn headers(vfs: &MemVfs) -> Vec<u8> {
        let file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
        let mut bytes = vec![0u8; PAGE * 2];
        file.read_at(0, &mut bytes).await.unwrap();
        bytes
    }

    let vfs = torn_chain_under_a_legacy_intent().await;
    let before = headers(&vfs).await;
    let opened = Db::open_read_only(vfs.clone(), KEK0, PAGE, REALM, options()).await;
    assert!(opened.is_err(), "a read-only handle cannot resume a rekey");
    drop(opened);
    assert_eq!(headers(&vfs).await, before);
}
