//! Follower mode: opening into it, promoting into it, and trading a handle's
//! sentinel for the exclusive writer one.

#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::Ordering;

use crate::crypto::SecretKey;
use crate::errors::PagedbError;
use crate::options::OpenOptions;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use super::super::super::mode::{
    ACQUISITION_LOCK_PATH, DbMode, FROZEN_READERS_LOCK_PATH, WRITER_LOCK_PATH,
};
use super::super::core::{Db, WriterState};
use super::super::restore_mode;
use super::modes::{DbModeCapabilities, map_lock_contention};

impl<V: Vfs + Clone> Db<V> {
    /// Promote a frozen read-only handle to Follower mode after excluding all
    /// other frozen readers and acquiring the writer sentinel.
    ///
    /// A restored directory records the promotion in its header. A later
    /// open still refuses to make it a Standalone writer.
    ///
    /// The handle seals its own pages under a random nonce prefix from here on.
    pub async fn promote_to_follower(mut self) -> Result<Self> {
        self.ensure_usable()?;
        self.require_mode(
            "promote_to_follower",
            DbMode::ReadOnly,
            DbModeCapabilities::promotes_to_follower,
        )?;
        self.take_exclusive_writer_sentinel("follower").await?;
        self.pager.use_local_nonce_prefix()?;
        self.pager.enable_write_access().await;
        self.record_follower_mode().await?;
        self.lock_required = true;
        self.mode = DbMode::Follower;
        Ok(self)
    }

    /// Open an existing store as a Follower: it applies a source's
    /// incremental snapshots and takes no writes of its own.
    ///
    /// - Holds the writer sentinel. Refuses with `ReadersPresent` or
    ///   `AlreadyOpen` while another handle holds the store.
    /// - Replays an incremental apply that a crash interrupted.
    /// - Reports `NotFound` for a missing store.
    /// - Records the promotion on a restored directory, as
    ///   [`Db::promote_to_follower`] does.
    /// - Changes nothing on an unstamped store until its first apply. That apply
    ///   makes every later `Standalone` open report `RestoredNotPromoted`.
    /// - Seals its own pages under a random nonce prefix drawn for this open.
    pub async fn open_follower(
        vfs: V,
        kek: impl Into<SecretKey>,
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        let kek = kek.into();
        let db = Self::open_with_mode(vfs, kek, None, page_size, realm, options, DbMode::Follower)
            .await?;
        db.record_follower_mode().await?;
        Ok(db)
    }

    /// Record in the header that a restored directory is now a Follower.
    /// It leaves an original store, or one already recorded, unchanged.
    async fn record_follower_mode(&self) -> Result<()> {
        let mut state = self.writer.lock().await;
        if state.restore_mode == restore_mode::READ_ONLY {
            self.persist_restore_mode(&mut state, restore_mode::FOLLOWER)
                .await?;
        }
        Ok(())
    }

    /// Record that this store takes delta pages, before the first one lands.
    ///
    /// Only a byte copy of a store reaches this with an unstamped header. A delta
    /// names the source's identity, and no API gives a second directory that
    /// identity unstamped. Later `Standalone` commits on the copy mix the source's
    /// counter stream with a local one, and they repeat the source's nonces.
    /// So from here it refuses `Standalone` as a restored directory does.
    ///
    /// The header reaches disk before the staged image copies it, so the image
    /// carries the stamp too. The target header lands in the other slot, so both
    /// slots of the published image hold it. A store already stamped takes no
    /// lock and writes nothing.
    #[cfg(not(target_arch = "wasm32"))]
    pub(in crate::txn::db) async fn record_first_apply(&self) -> Result<()> {
        if !self.first_apply_unstamped.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut state = self.writer.lock().await;
        self.ensure_usable()?;
        if state.restore_mode == restore_mode::STANDALONE {
            self.persist_restore_mode(&mut state, restore_mode::FOLLOWER)
                .await?;
        }
        self.first_apply_unstamped.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Replace this handle's sentinels with the exclusive writer sentinel.
    ///
    /// Refuses with `ReadersPresent` while another frozen reader holds the
    /// store, and with `AlreadyOpen` while a writer does. `role` names the
    /// requester in lock diagnostics.
    pub(in crate::txn::db) async fn take_exclusive_writer_sentinel(
        &mut self,
        role: &'static str,
    ) -> Result<()> {
        let acquisition = self.vfs.lock_exclusive(ACQUISITION_LOCK_PATH).await?;
        self.sentinel_locks.clear();
        let frozen_probe = self
            .vfs
            .lock_exclusive(FROZEN_READERS_LOCK_PATH)
            .await
            .map_err(|error| {
                map_lock_contention(error, || {
                    crate::diag::lock_rejected(role, FROZEN_READERS_LOCK_PATH, "readers_present");
                    PagedbError::ReadersPresent
                })
            })?;
        drop(frozen_probe);
        let writer_lock = self
            .vfs
            .lock_exclusive(WRITER_LOCK_PATH)
            .await
            .map_err(|error| {
                map_lock_contention(error, || {
                    crate::diag::lock_rejected(role, WRITER_LOCK_PATH, "already_open");
                    PagedbError::AlreadyOpen
                })
            })?;
        drop(acquisition);
        crate::diag::lock_acquired(role, WRITER_LOCK_PATH);
        self.sentinel_locks.push(writer_lock);
        Ok(())
    }

    /// Record a restore-mode transition with a header-only commit.
    ///
    /// Only the HMAC-authenticated header is written, so the commit seals no
    /// page and consumes no nonce.
    async fn persist_restore_mode(&self, state: &mut WriterState, mode: u8) -> Result<()> {
        let cursor = self.pager.header_cursor()?;
        let seq = cursor.next_seq()?;
        let counter_anchor = self.pager.pending_anchor();
        let mut fields = self.state_header_fields(state, seq, counter_anchor)?;
        fields.restore_mode = mode;
        let hk = self.hk.read().clone();
        let slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk,
            &fields,
            cursor.slot,
            self.page_size,
        )
        .await?;
        self.pager.note_header_written(HeaderCursor { slot, seq });
        self.pager.commit_anchor(counter_anchor)?;
        state.restore_mode = mode;
        Ok(())
    }
}
