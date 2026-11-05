//! Drop guards that keep a cancelled write-side future from leaving the handle
//! or the page cache in a half-published state.

use crate::CommitId;
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

/// `Db` constructors for the guards above.
impl<V: Vfs + Clone> Db<V> {
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
    use crate::pager::PageKind;
    use crate::pager::core::FileKey;
    use crate::pager::format::data_page::body_capacity;
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
