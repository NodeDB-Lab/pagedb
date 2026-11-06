//! Drop guards that keep a cancelled write-side future from leaving the handle
//! or the page cache in a half-published state.

use std::sync::Arc;

use crate::CommitId;
use crate::errors::PagedbError;
use crate::pager::header::HeaderWriteError;
use crate::vfs::Vfs;

use super::core::Db;

/// Poisons the handle when dropped armed.
///
/// A caller can drop a commit future at any await. `Drop` is then the only code
/// that still runs, and it cannot await the rest of publication.
///
/// The backing I/O can outlive the dropped future on a blocking pool. An armed
/// guard therefore treats the outcome of the durable write as unknown. A reopen
/// settles it.
///
/// Declare the guard after the writer and visibility guards. It then poisons
/// before either lock releases, so a waiter that gets the lock sees the poison.
#[must_use = "dropping an armed guard poisons the handle"]
pub(crate) struct DurablePublishGuard<'db, V: Vfs + Clone> {
    db: &'db Db<V>,
    commit: CommitId,
    armed: bool,
}

impl<V: Vfs + Clone> DurablePublishGuard<'_, V> {
    /// Memory now matches the durable state, or the durable write did not happen.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }

    /// Turn a failed header write into the error its caller returns.
    ///
    /// When no byte landed, the previous header stands. The guard disarms and the
    /// cause returns as it is, so the handle stays usable.
    ///
    /// A failed write or sync can leave the new header durable while this handle
    /// keeps the old state. The next commit then overwrites pages that header
    /// names. So the handle poisons, and only a reopen can read which header won.
    /// The returned error carries the cause and claims no durable commit.
    pub(crate) fn header_write_failed(self, error: HeaderWriteError) -> PagedbError {
        let commit = self.commit;
        let source = match error {
            HeaderWriteError::NotStarted(cause) => {
                self.disarm();
                return cause;
            }
            HeaderWriteError::OutcomeUnknown(cause) => Arc::new(cause),
        };
        tracing::error!(
            commit = commit.0,
            error = %source,
            "header write failed, so the durable header is unknown; reopen required"
        );
        self.db
            .poison_header_outcome_unknown(commit, Arc::clone(&source));
        self.disarm();
        PagedbError::commit_outcome_unknown_shared(commit, source)
    }
}

impl<V: Vfs + Clone> Drop for DurablePublishGuard<'_, V> {
    fn drop(&mut self) {
        if self.armed {
            self.db.poison(self.commit);
        }
    }
}

/// Drops resident main pages when dropped armed.
///
/// Staged pages sit in the cache under ids the live image also uses. A dirty one
/// reaches the live file with the next `flush_main`. A clean one answers the next
/// read of that id. Both must go when the staging future ends without publishing.
///
/// Both cache calls are synchronous, so `Drop` can run them. A cache fault stays
/// latched, and every later operation on the cache reports it.
#[must_use = "dropping an armed guard drops every resident main page"]
pub(crate) struct UnpublishedPagesGuard<'db, V: Vfs + Clone> {
    db: &'db Db<V>,
    armed: bool,
}

impl<V: Vfs + Clone> UnpublishedPagesGuard<'_, V> {
    /// The staged pages are now the published image.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl<V: Vfs + Clone> Drop for UnpublishedPagesGuard<'_, V> {
    fn drop(&mut self) {
        if self.armed {
            self.db.pager.discard_dirty_main();
            let _ = self.db.pager.reset_main_pages();
        }
    }
}

/// Drops one apply-journal sidecar's in-memory state when dropped armed.
///
/// Staged journal pages stay dirty until `flush_journal` returns. No later flush
/// names this journal id, and dirty pages cannot be evicted. Without this guard
/// they hold their cache budget until a reopen. The id is never reused, so its
/// in-memory state has no later use.
#[cfg(not(target_arch = "wasm32"))]
#[must_use = "dropping an armed guard drops the staged journal pages"]
pub(crate) struct UnflushedJournalGuard<'db, V: Vfs + Clone> {
    db: &'db Db<V>,
    journal_id: [u8; 16],
    armed: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl<V: Vfs + Clone> UnflushedJournalGuard<'_, V> {
    /// The journal pages reached the sidecar file.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<V: Vfs + Clone> Drop for UnflushedJournalGuard<'_, V> {
    fn drop(&mut self) {
        if self.armed {
            self.db.pager.discard_unflushed_journal(self.journal_id);
        }
    }
}

/// `Db` constructors for the guards above.
impl<V: Vfs + Clone> Db<V> {
    /// Arm a guard that drops this journal's staged pages unless it is disarmed.
    /// Call this before the first `stage_journal_page` for `journal_id`.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn discard_unflushed_journal_on_drop(
        &self,
        journal_id: [u8; 16],
    ) -> UnflushedJournalGuard<'_, V> {
        UnflushedJournalGuard {
            db: self,
            journal_id,
            armed: true,
        }
    }

    /// Arm a guard that poisons this handle at `commit` unless it is disarmed.
    /// Call this before the rename or header write that makes state durable.
    pub(crate) fn arm_durable_publish(&self, commit: CommitId) -> DurablePublishGuard<'_, V> {
        DurablePublishGuard {
            db: self,
            commit,
            armed: true,
        }
    }

    /// Arm a guard that drops resident main pages unless it is disarmed.
    /// Call this while holding the writer lock, before staging unpublished pages.
    pub(crate) fn discard_unpublished_pages_on_drop(&self) -> UnpublishedPagesGuard<'_, V> {
        UnpublishedPagesGuard {
            db: self,
            armed: true,
        }
    }
}

#[cfg(test)]
mod guard_tests {
    use std::sync::Arc;

    use crate::pager::PageKind;
    use crate::pager::core::FileKey;
    use crate::pager::format::data_page::body_capacity;
    use crate::pager::header::HeaderWriteError;
    use crate::vfs::memory::MemVfs;
    use crate::{CommitId, Db, OpenOptions, PagedbError, RealmId};

    const PAGE: usize = 4096;
    const REALM: RealmId = RealmId::new([0x6A; 16]);

    async fn db() -> Db<MemVfs> {
        Db::open(
            MemVfs::new(),
            [0x6B; 32],
            PAGE,
            REALM,
            OpenOptions::default(),
        )
        .await
        .unwrap()
    }

    async fn write_dirty_page(db: &Db<MemVfs>) -> u64 {
        let page_id = db.writer.lock().await.next_page_id + 1_000;
        db.pager
            .write_main_page(
                page_id,
                REALM,
                PageKind::Free,
                &vec![0xAB; body_capacity(PAGE)],
            )
            .await
            .unwrap();
        page_id
    }

    fn dirty_pages(db: &Db<MemVfs>) -> Vec<u64> {
        db.pager
            .inner
            .buffer_pool
            .lock()
            .dirty_for_file(FileKey::Main)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn durable_publish_guard_poisons_the_handle_when_dropped_armed() {
        let db = db().await;
        let commit = CommitId::new(7);
        drop(db.arm_durable_publish(commit));
        assert!(matches!(
            db.ensure_usable(),
            Err(PagedbError::DurablyCommittedButUnpublished { commit: poisoned }) if poisoned == commit
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn durable_publish_guard_leaves_the_handle_usable_when_disarmed() {
        let db = db().await;
        db.arm_durable_publish(CommitId::new(7)).disarm();
        db.ensure_usable().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_header_write_poisons_with_the_unknown_outcome_error() {
        let db = db().await;
        let commit = CommitId::new(7);
        let returned = db
            .arm_durable_publish(commit)
            .header_write_failed(HeaderWriteError::OutcomeUnknown(PagedbError::NoSpace));
        let assert_carries_the_cause = |error: PagedbError| {
            assert!(error.to_string().contains("no space"), "display: {error}");
            assert!(matches!(
                error,
                PagedbError::CommitOutcomeUnknown { commit: poisoned, source }
                    if poisoned == commit && matches!(*source, PagedbError::NoSpace)
            ));
        };
        assert_carries_the_cause(returned);
        assert_carries_the_cause(db.ensure_usable().unwrap_err());
    }

    /// No byte landed, so the previous header is known to stand.
    #[tokio::test(flavor = "current_thread")]
    async fn a_header_write_that_never_started_returns_its_cause_without_poison() {
        let db = db().await;
        let returned = db
            .arm_durable_publish(CommitId::new(7))
            .header_write_failed(HeaderWriteError::NotStarted(PagedbError::NoSpace));
        assert!(matches!(returned, PagedbError::NoSpace));
        db.ensure_usable().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_first_poison_of_a_handle_stands() {
        let db = db().await;
        db.poison_header_outcome_unknown(CommitId::new(7), Arc::new(PagedbError::NoSpace));
        db.poison(CommitId::new(8));
        assert!(matches!(
            db.ensure_usable(),
            Err(PagedbError::CommitOutcomeUnknown { commit, .. }) if commit == CommitId::new(7)
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn unflushed_journal_guard_drops_staged_pages_when_dropped_armed() {
        let db = db().await;
        let journal_id = [0x5A; 16];
        let guard = db.discard_unflushed_journal_on_drop(journal_id);
        db.pager
            .stage_journal_page(journal_id, 0, REALM, &vec![0xAB; body_capacity(PAGE)])
            .await
            .unwrap();
        assert_eq!(db.pager.inner.segment_cache.lock().dirty_len(), 1);
        drop(guard);
        assert_eq!(db.pager.inner.segment_cache.lock().dirty_len(), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn unflushed_journal_guard_keeps_flushed_pages_when_disarmed() {
        let db = db().await;
        let journal_id = [0x5B; 16];
        let guard = db.discard_unflushed_journal_on_drop(journal_id);
        db.pager
            .stage_journal_page(journal_id, 0, REALM, &vec![0xAB; body_capacity(PAGE)])
            .await
            .unwrap();
        db.pager.flush_journal(journal_id, REALM).await.unwrap();
        guard.disarm();
        let _page = db
            .pager
            .read_journal_page(journal_id, 0, REALM)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unpublished_pages_guard_drops_dirty_pages_when_dropped_armed() {
        let db = db().await;
        let guard = db.discard_unpublished_pages_on_drop();
        write_dirty_page(&db).await;
        assert_eq!(dirty_pages(&db).len(), 1);
        drop(guard);
        assert_eq!(dirty_pages(&db), Vec::<u64>::new());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unpublished_pages_guard_keeps_dirty_pages_when_disarmed() {
        let db = db().await;
        let guard = db.discard_unpublished_pages_on_drop();
        let page_id = write_dirty_page(&db).await;
        guard.disarm();
        assert_eq!(dirty_pages(&db), vec![page_id]);
        db.pager.discard_dirty_main();
    }
}
