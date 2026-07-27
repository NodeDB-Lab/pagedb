//! Interruption of the nonce-anchor commit that follows a durable header.
//!
//! `Pager::commit_anchor` performs no I/O, so no VFS decorator can refuse it —
//! yet every commit path treats its failure as poisoning, because a handle that
//! cannot promise the anchor is durable cannot promise the next nonce is
//! unused. That made the most consequential branch in the commit tail the one
//! branch nothing exercised. The pager's own one-shot fault reaches it.

use crate::pager::anchor::AnchorTestFault;
use crate::vfs::memory::MemVfs;
use crate::{Db, PagedbError, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [0x2B; 32];
const REALM: RealmId = RealmId::new([0x7C; 16]);
const KEYS: u32 = 8;

fn key(index: u32) -> Vec<u8> {
    format!("anchored-{index:03}").into_bytes()
}

/// The header is already durable when the anchor commit runs, so the store the
/// crash leaves behind is a complete one — but the *handle* must not keep
/// serving from it, and the reopened writer must accept it without repair.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_anchor_commit_poisons_the_handle_and_leaves_a_whole_store() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"base", b"before").await.unwrap();
    txn.commit().await.unwrap();
    let base_commit = db.latest_commit();

    db.pager.interrupt_anchor_after(AnchorTestFault::Commit);
    let mut txn = db.begin_write().await.unwrap();
    for index in 0..KEYS {
        txn.put(&key(index), b"anchored").await.unwrap();
    }
    let error = txn
        .commit()
        .await
        .expect_err("a refused anchor commit must not report success");
    let unpublished = match error {
        PagedbError::DurablyCommittedButUnpublished { commit } => commit,
        other => panic!("expected an unpublished-commit refusal, got {other:?}"),
    };
    assert!(unpublished > base_commit);

    // The published snapshot never advanced, and the handle refuses every
    // state-dependent operation rather than answering from a commit whose
    // anchor it could not make durable.
    assert_eq!(db.latest_commit(), base_commit);
    assert!(matches!(
        db.begin_read().await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));
    assert!(matches!(
        db.begin_write().await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));
    drop(db);

    let reopened = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"base").await.unwrap().as_deref(),
        Some(b"before".as_slice()),
        "the commit preceding the interruption must survive it"
    );
    let mut present = 0u32;
    for index in 0..KEYS {
        if reader.get(&key(index)).await.unwrap().is_some() {
            present += 1;
        }
    }
    assert!(
        present == 0 || present == KEYS,
        "the interrupted transaction landed in part: {present} of {KEYS} keys"
    );
    let observed = reopened.latest_commit();
    assert_eq!(
        observed == unpublished,
        present == KEYS,
        "the recovered commit id and the recovered data must describe the same transaction"
    );
    assert!(observed == base_commit || observed == unpublished);
    drop(reader);

    let report = crate::recovery::deep_walk::run_deep_walk(&reopened)
        .await
        .unwrap();
    assert!(
        report.is_clean(),
        "an interrupted anchor commit left the store needing repair: {report:?}"
    );
}

/// A poisoned handle stays poisoned: the one-shot is spent, so a retry meets
/// no fault at all and must still be refused. Anything else would let a
/// caller commit onto a snapshot the handle already declined to publish.
#[tokio::test(flavor = "current_thread")]
async fn a_poisoned_handle_refuses_a_retry_even_once_the_fault_is_spent() {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs, KEK, PAGE, REALM).await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"base", b"before").await.unwrap();
    txn.commit().await.unwrap();

    db.pager.interrupt_anchor_after(AnchorTestFault::Commit);
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"interrupted", b"value").await.unwrap();
    assert!(txn.commit().await.is_err());

    assert!(matches!(
        db.begin_write().await,
        Err(PagedbError::DurablyCommittedButUnpublished { .. })
    ));
}
