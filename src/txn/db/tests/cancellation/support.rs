//! Fixtures shared by the cancellation tests.

use crate::options::{OpenOptions, RetainPolicy};
use crate::vfs::Vfs;
use crate::vfs::gated::GatedVfs;
use crate::{CommitId, Db, PagedbError, RealmId, Result};

pub(super) const PAGE: usize = 4096;
pub(super) const KEK: [u8; 32] = [0x3D; 32];
pub(super) const REALM: RealmId = RealmId::new([0x4E; 16]);

const ROWS: u32 = 300;
/// A value past the inline threshold that fits in one overflow page.
const VALUE_LEN: usize = 3000;
/// The small pool makes a repack flush often, which gives its gates places to
/// park inside one source batch.
const POOL_PAGES: usize = 16;

pub(super) fn row_key(row: u32) -> Vec<u8> {
    format!("row-{row:05}").into_bytes()
}

pub(super) fn row_value(row: u32) -> Vec<u8> {
    let generation = u8::from((40..60).contains(&row));
    let mut value = vec![generation; VALUE_LEN];
    value[..4].copy_from_slice(&row.to_le_bytes());
    value
}

pub(super) fn repack_options() -> OpenOptions {
    OpenOptions::default()
        .with_commit_history_retain(RetainPolicy::Disabled)
        .with_buffer_pool_pages(POOL_PAGES)
}

/// A store with a non-empty free list, so `compact_now` runs its repack.
pub(super) async fn store_with_free_pages() -> (GatedVfs, Db<GatedVfs>) {
    let vfs = GatedVfs::new();
    let db = Db::open(vfs.clone(), KEK, PAGE, REALM, repack_options())
        .await
        .unwrap();
    let mut txn = db.begin_write().await.unwrap();
    for row in 0..ROWS {
        let value = vec![0u8; VALUE_LEN];
        txn.put(&row_key(row), &value).await.unwrap();
    }
    txn.commit().await.unwrap();
    let mut txn = db.begin_write().await.unwrap();
    for row in 0..ROWS {
        txn.put(&row_key(row), &row_value(row)).await.unwrap();
    }
    txn.commit().await.unwrap();
    assert_ne!(
        db.writer.lock().await.free_list_root_page_id,
        0,
        "setup error: the free list is empty, so compact_now skips its repack"
    );
    (vfs, db)
}

pub(super) async fn assert_every_row_reads_back<V: Vfs + Clone>(db: &Db<V>) {
    let reader = db.begin_read().await.unwrap();
    for row in 0..ROWS {
        let value = reader
            .get(&row_key(row))
            .await
            .unwrap_or_else(|error| panic!("row {row} is unreadable: {error:?}"));
        assert_eq!(
            value.as_deref(),
            Some(row_value(row).as_slice()),
            "row {row} has the wrong value"
        );
    }
}

/// The commit a poison error names. Panics on any other outcome.
pub(super) fn poisoned_commit<T>(outcome: Result<T>) -> CommitId {
    match outcome {
        Err(PagedbError::DurablyCommittedButUnpublished { commit }) => commit,
        Err(error) => panic!("expected the durable-but-unpublished error, got {error:?}"),
        Ok(_) => panic!("expected the durable-but-unpublished error, the call succeeded"),
    }
}

/// Byte offset of the header slot the next header write targets.
pub(super) fn next_header_offset<V: Vfs + Clone>(db: &Db<V>) -> u64 {
    db.pager.header_cursor().unwrap().slot.other().page_id() * PAGE as u64
}

/// The next commit id this handle assigns.
pub(super) fn next_commit<V: Vfs + Clone>(db: &Db<V>) -> CommitId {
    CommitId::new(db.latest_commit().value() + 1)
}
