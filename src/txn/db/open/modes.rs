//! Mode policy, sentinel acquisition, and public mode constructors.

use crate::errors::PagedbError;
use crate::options::OpenOptions;
use crate::vfs::Vfs;
use crate::vfs::types::OpenMode;
use crate::{RealmId, Result};

use super::super::super::mode::{
    ACQUISITION_LOCK_PATH, DbMode, FROZEN_READERS_LOCK_PATH, OBSERVERS_LOCK_PATH, WRITER_LOCK_PATH,
};
use super::super::core::Db;
use super::super::util::peek_restore_mode;

#[derive(Clone, Copy)]
pub(super) enum PersistentAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy)]
pub(super) enum RecoveryAuthority {
    VerifyOnly,
    ApplyOnly,
    Standalone,
}

#[derive(Clone, Copy)]
pub(super) enum LongLivedLock {
    Writer,
    FrozenReader,
    Observer,
}

/// The complete open-time authority matrix for a handle mode.
#[derive(Clone, Copy)]
pub(in crate::txn::db) struct DbModeCapabilities {
    persistent_access: PersistentAccess,
    recovery_authority: RecoveryAuthority,
    long_lived_lock: LongLivedLock,
    /// Observer retries are a read-path tolerance, not an access authority.
    allows_observer_retry: bool,
}

impl DbModeCapabilities {
    #[must_use]
    pub(in crate::txn::db) const fn bootstraps(self) -> bool {
        matches!(self.recovery_authority, RecoveryAuthority::Standalone)
    }

    #[must_use]
    pub(in crate::txn::db) const fn main_db_open_mode(self) -> OpenMode {
        match self.persistent_access {
            PersistentAccess::ReadOnly => OpenMode::Read,
            PersistentAccess::ReadWrite => OpenMode::ReadWrite,
        }
    }

    #[must_use]
    pub(in crate::txn::db) const fn read_only_file_access(self) -> bool {
        matches!(self.persistent_access, PersistentAccess::ReadOnly)
    }

    #[must_use]
    pub(in crate::txn::db) const fn allows_user_writes(self) -> bool {
        matches!(self.recovery_authority, RecoveryAuthority::Standalone)
    }

    #[must_use]
    pub(in crate::txn::db) const fn applies_interrupted_apply(self) -> bool {
        matches!(
            self.recovery_authority,
            RecoveryAuthority::ApplyOnly | RecoveryAuthority::Standalone
        )
    }

    #[must_use]
    pub(in crate::txn::db) const fn runs_standalone_recovery(self) -> bool {
        matches!(self.recovery_authority, RecoveryAuthority::Standalone)
    }

    #[must_use]
    pub(in crate::txn::db) const fn rejects_unpromoted_restore(self) -> bool {
        self.runs_standalone_recovery()
    }

    #[must_use]
    const fn long_lived_lock(self) -> LongLivedLock {
        self.long_lived_lock
    }

    #[must_use]
    pub(in crate::txn::db) const fn allows_observer_retry(self) -> bool {
        self.allows_observer_retry
    }
}

impl DbMode {
    #[must_use]
    pub(in crate::txn::db) const fn open_capabilities(self) -> DbModeCapabilities {
        match self {
            Self::Standalone => DbModeCapabilities {
                persistent_access: PersistentAccess::ReadWrite,
                recovery_authority: RecoveryAuthority::Standalone,
                long_lived_lock: LongLivedLock::Writer,
                allows_observer_retry: false,
            },
            Self::Follower => DbModeCapabilities {
                persistent_access: PersistentAccess::ReadWrite,
                recovery_authority: RecoveryAuthority::ApplyOnly,
                long_lived_lock: LongLivedLock::Writer,
                allows_observer_retry: false,
            },
            Self::ReadOnly => DbModeCapabilities {
                persistent_access: PersistentAccess::ReadOnly,
                recovery_authority: RecoveryAuthority::VerifyOnly,
                long_lived_lock: LongLivedLock::FrozenReader,
                allows_observer_retry: false,
            },
            Self::Observer => DbModeCapabilities {
                persistent_access: PersistentAccess::ReadOnly,
                recovery_authority: RecoveryAuthority::VerifyOnly,
                long_lived_lock: LongLivedLock::Observer,
                allows_observer_retry: true,
            },
        }
    }
}

impl<V: Vfs + Clone> Db<V> {
    /// Open a database in Standalone mode.
    pub async fn open(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_with_mode(vfs, kek, page_size, realm, options, DbMode::Standalone).await
    }

    /// Open a frozen-snapshot database without write access.
    pub async fn open_read_only(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_with_mode(vfs, kek, page_size, realm, options, DbMode::ReadOnly).await
    }

    /// Open a best-effort read-only view of a database that may have a writer.
    pub async fn open_observer(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_with_mode(vfs, kek, page_size, realm, options, DbMode::Observer).await
    }

    async fn open_with_mode(
        vfs: V,
        kek: [u8; 32],
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        mode: DbMode,
    ) -> Result<Self> {
        let capabilities = mode.open_capabilities();
        let options = if capabilities.allows_observer_retry() {
            options
        } else {
            OpenOptions {
                observer_retry_count: 0,
                ..options
            }
        };
        let mut locks = Vec::new();

        // A missing database is a terminal read-only error. Probe before
        // acquiring a lock because native lock backends materialize sentinel
        // files when locking an otherwise empty directory.
        if !capabilities.bootstraps() && !main_db_exists(&vfs).await? {
            return Err(PagedbError::NotFound);
        }

        let acquisition = vfs.lock_exclusive(ACQUISITION_LOCK_PATH).await?;
        let main_db_exists = {
            let exists = main_db_exists(&vfs).await?;
            if !exists && !capabilities.bootstraps() {
                return Err(PagedbError::NotFound);
            }
            if exists
                && capabilities.rejects_unpromoted_restore()
                && peek_restore_mode(&vfs, &kek, page_size).await? == 2
            {
                return Err(PagedbError::RestoredNotPromoted);
            }
            acquire_interlocking_mode_lock(&vfs, capabilities, &mut locks).await?;
            drop(acquisition);
            exists
        };

        let mut db = if main_db_exists {
            Self::open_existing_inner(vfs, kek, page_size, realm, options, mode).await?
        } else {
            Self::open_internal_with_options(vfs, kek, page_size, realm, options).await?
        };
        db.mode = mode;
        db.sentinel_locks = locks;
        Ok(db)
    }

    /// Promote a frozen read-only handle to Follower mode after excluding all
    /// other frozen readers and acquiring the writer sentinel.
    pub async fn promote_to_follower(mut self) -> Result<Self> {
        self.ensure_usable()?;
        if self.mode != DbMode::ReadOnly {
            return Err(PagedbError::Unsupported);
        }
        let acquisition = self.vfs.lock_exclusive(ACQUISITION_LOCK_PATH).await?;
        self.sentinel_locks.clear();
        let frozen_probe = self
            .vfs
            .lock_exclusive(FROZEN_READERS_LOCK_PATH)
            .await
            .map_err(|_| PagedbError::ReadersPresent)?;
        drop(frozen_probe);
        let writer_lock = self
            .vfs
            .lock_exclusive(WRITER_LOCK_PATH)
            .await
            .map_err(|_| PagedbError::AlreadyOpen)?;
        drop(acquisition);
        self.pager.enable_write_access().await;
        self.sentinel_locks.push(writer_lock);
        self.mode = DbMode::Follower;
        Ok(self)
    }
}

async fn main_db_exists<V: Vfs>(vfs: &V) -> Result<bool> {
    match vfs.open("/main.db", OpenMode::Read).await {
        Ok(file) => {
            drop(file);
            Ok(true)
        }
        Err(PagedbError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

async fn acquire_interlocking_mode_lock<V: Vfs>(
    vfs: &V,
    capabilities: DbModeCapabilities,
    locks: &mut Vec<V::LockHandle>,
) -> Result<()> {
    match capabilities.long_lived_lock() {
        LongLivedLock::Writer => {
            let frozen_probe = vfs
                .lock_exclusive(FROZEN_READERS_LOCK_PATH)
                .await
                .map_err(|_| PagedbError::ReadersPresent)?;
            drop(frozen_probe);
            acquire_long_lived_lock(vfs, LongLivedLock::Writer, locks).await
        }
        LongLivedLock::FrozenReader => {
            let writer_probe = vfs
                .lock_exclusive(WRITER_LOCK_PATH)
                .await
                .map_err(|_| PagedbError::WriterPresent)?;
            drop(writer_probe);
            acquire_long_lived_lock(vfs, LongLivedLock::FrozenReader, locks).await
        }
        LongLivedLock::Observer => {
            acquire_long_lived_lock(vfs, LongLivedLock::Observer, locks).await
        }
    }
}

async fn acquire_long_lived_lock<V: Vfs>(
    vfs: &V,
    lock: LongLivedLock,
    locks: &mut Vec<V::LockHandle>,
) -> Result<()> {
    let handle = match lock {
        LongLivedLock::Writer => vfs
            .lock_exclusive(WRITER_LOCK_PATH)
            .await
            .map_err(|_| PagedbError::AlreadyOpen)?,
        LongLivedLock::FrozenReader => vfs
            .lock_shared(FROZEN_READERS_LOCK_PATH)
            .await
            .map_err(|_| PagedbError::AlreadyLocked)?,
        LongLivedLock::Observer => vfs
            .lock_shared(OBSERVERS_LOCK_PATH)
            .await
            .map_err(|_| PagedbError::AlreadyLocked)?,
    };
    locks.push(handle);
    Ok(())
}
