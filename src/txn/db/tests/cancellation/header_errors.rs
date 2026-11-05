//! A header write that returns `Err`. The handle cannot tell which header is
//! durable, so it poisons with a typed error that claims no durable commit.

use crate::catalog::codec::RealmQuotas;
use crate::options::OpenOptions;
use crate::recovery::deep_walk::run_deep_walk;
use crate::vfs::gated::GatedVfs;
use crate::{CommitId, Db, PagedbError, Result};

use super::support::{KEK, PAGE, REALM, next_commit, next_header_offset};

async fn store_with_base_commit() -> (GatedVfs, Db<GatedVfs>) {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"base", b"before").await.unwrap();
    txn.commit().await.unwrap();
    (vfs, db)
}

fn outcome_unknown_commit<T>(outcome: Result<T>) -> CommitId {
    match outcome {
        Err(PagedbError::CommitOutcomeUnknown { commit, source }) => {
            assert!(
                matches!(*source, PagedbError::Io(_)),
                "the error lost its cause: {source:?}"
            );
            commit
        }
        Err(error) => panic!("expected the unknown-outcome error, got {error:?}"),
        Ok(_) => panic!("expected the unknown-outcome error, the call succeeded"),
    }
}

/// The poison repeats the cause on later calls, and the message names it.
#[tokio::test(flavor = "current_thread")]
async fn the_unknown_outcome_error_displays_its_cause_on_every_call() {
    let (vfs, db) = store_with_base_commit().await;

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"landed", b"after").await.unwrap();
    vfs.fail_sync_after_next_write_at(&db.main_db_path, next_header_offset(&db));

    for error in [
        txn.commit().await.unwrap_err(),
        db.ensure_usable().unwrap_err(),
    ] {
        assert!(
            error.to_string().contains("injected I/O fault"),
            "display: {error}"
        );
    }
}

/// The open failed before the write, so no byte landed. The outcome is known: the
/// previous header stands. The caller gets the cause, and the handle keeps working.
#[tokio::test(flavor = "current_thread")]
async fn commit_with_a_failed_header_open_stays_a_plain_error_and_the_handle_works() {
    let (vfs, db) = store_with_base_commit().await;
    let base = db.latest_commit();

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"lost", b"after").await.unwrap();
    vfs.fail_next_read_write_open(&db.main_db_path);
    assert!(matches!(txn.commit().await, Err(PagedbError::Io(_))));

    db.ensure_usable().unwrap();
    assert_eq!(db.latest_commit(), base);
    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"next", b"writer").await.unwrap();
    let next = txn.commit().await.unwrap();
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(reopened.latest_commit(), next);
    let reader = reopened.begin_read().await.unwrap();
    assert!(reader.get(b"lost").await.unwrap().is_none());
    assert_eq!(
        reader.get(b"next").await.unwrap().as_deref(),
        Some(b"writer".as_slice())
    );
    drop(reader);
    let report = run_deep_walk(&reopened).await.unwrap();
    assert!(report.is_clean(), "the reopened store: {report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn realm_quota_update_with_a_failed_header_open_stays_a_plain_error() {
    let (vfs, db) = store_with_base_commit().await;
    vfs.fail_next_read_write_open(&db.main_db_path);

    assert!(matches!(
        db.set_realm_quotas(REALM, RealmQuotas::default()).await,
        Err(PagedbError::Io(_))
    ));

    db.ensure_usable().unwrap();
    db.set_realm_quotas(REALM, RealmQuotas::default())
        .await
        .unwrap();
}

/// The new header reached the file and the sync reported failure. The reopen
/// finds that header, so the old handle must not write over the pages it names.
#[tokio::test(flavor = "current_thread")]
async fn commit_with_a_failed_header_sync_poisons_and_reopens_at_the_landed_commit() {
    let (vfs, db) = store_with_base_commit().await;
    let base = db.latest_commit();
    let expected = next_commit(&db);

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"landed", b"after").await.unwrap();
    vfs.fail_sync_after_next_write_at(&db.main_db_path, next_header_offset(&db));

    assert_eq!(outcome_unknown_commit(txn.commit().await), expected);
    assert_eq!(outcome_unknown_commit(db.begin_write().await), expected);
    assert_eq!(outcome_unknown_commit(db.begin_read().await), expected);
    assert_eq!(db.latest_commit(), base);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(reopened.latest_commit(), expected);
    let reader = reopened.begin_read().await.unwrap();
    assert_eq!(
        reader.get(b"landed").await.unwrap().as_deref(),
        Some(b"after".as_slice())
    );
    drop(reader);
    let report = run_deep_walk(&reopened).await.unwrap();
    assert!(report.is_clean(), "the reopened store: {report:?}");
}

/// No header byte landed, so the reopen finds the old commit. The handle poisons
/// all the same, because an `Err` alone cannot tell this case from the sync case.
#[tokio::test(flavor = "current_thread")]
async fn commit_with_a_failed_header_write_poisons_and_reopens_at_the_old_commit() {
    let (vfs, db) = store_with_base_commit().await;
    let base = db.latest_commit();
    let expected = next_commit(&db);

    let mut txn = db.begin_write().await.unwrap();
    txn.put(b"lost", b"after").await.unwrap();
    vfs.fail_next_write_at(&db.main_db_path, next_header_offset(&db));

    assert_eq!(outcome_unknown_commit(txn.commit().await), expected);
    assert_eq!(outcome_unknown_commit(db.begin_write().await), expected);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(reopened.latest_commit(), base);
    let reader = reopened.begin_read().await.unwrap();
    assert!(reader.get(b"lost").await.unwrap().is_none());
    drop(reader);
    let report = run_deep_walk(&reopened).await.unwrap();
    assert!(report.is_clean(), "the reopened store: {report:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn realm_quota_update_with_a_failed_header_sync_poisons_and_reopens_with_the_quota() {
    let (vfs, db) = store_with_base_commit().await;
    let latest = db.latest_commit();
    let quotas = RealmQuotas {
        max_segment_bytes: Some(4096),
        ..RealmQuotas::default()
    };
    vfs.fail_sync_after_next_write_at(&db.main_db_path, next_header_offset(&db));

    assert_eq!(
        outcome_unknown_commit(db.set_realm_quotas(REALM, quotas).await),
        latest
    );
    assert_eq!(outcome_unknown_commit(db.realm_quotas(REALM).await), latest);
    drop(db);

    let reopened = Db::open(vfs, KEK, PAGE, REALM, OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .realm_quotas(REALM)
            .await
            .unwrap()
            .max_segment_bytes,
        Some(4096)
    );
}
