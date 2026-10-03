//! Mode policy, sentinel acquisition, and public mode constructors.

use crate::crypto::SecretKey;
use crate::errors::PagedbError;
use crate::options::OpenOptions;
use crate::vfs::Vfs;
use crate::vfs::types::OpenMode;
use crate::{RealmId, Result};

use super::super::super::mode::{
    ACQUISITION_LOCK_PATH, DbMode, FROZEN_READERS_LOCK_PATH, OBSERVERS_LOCK_PATH, WRITER_LOCK_PATH,
};
use super::super::core::Db;

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

/// The complete authority matrix for a handle mode.
///
/// Both the open flow and every runtime mode gate resolve against this one
/// table, so "which modes may do X" is stated once rather than re-derived by
/// each public method from its own `matches!` on `DbMode`.
#[derive(Clone, Copy)]
pub(crate) struct DbModeCapabilities {
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

    /// Write transactions and segment creation: only a full writer may add
    /// user data to the store.
    #[must_use]
    pub(crate) const fn allows_user_writes(self) -> bool {
        matches!(self.recovery_authority, RecoveryAuthority::Standalone)
    }

    /// Whole-store rewrites that publish no new user data but relocate or
    /// re-seal every byte — compaction's dense repack, an online rekey. Same
    /// authority as a user write, stated separately because it is a different
    /// claim: these paths own the allocator and the key epoch, not the data.
    #[must_use]
    pub(crate) const fn allows_store_maintenance(self) -> bool {
        self.runs_standalone_recovery()
    }

    /// Applying an incremental snapshot. Only an apply-authority handle
    /// carries the base-commit identity a delta reconciles against, and only
    /// it is licensed to install a producer's page space over its own.
    #[must_use]
    pub(crate) const fn applies_incremental_snapshots(self) -> bool {
        matches!(self.recovery_authority, RecoveryAuthority::ApplyOnly)
    }

    /// Promotion to `Follower`. The promotion trades the frozen-reader
    /// sentinel for the writer sentinel, so only the mode that actually holds
    /// the frozen-reader lock has anything to trade — which is what separates
    /// `ReadOnly` from `Observer` here, since their access and recovery
    /// authority are otherwise identical.
    #[must_use]
    pub(crate) const fn promotes_to_follower(self) -> bool {
        matches!(self.long_lived_lock, LongLivedLock::FrozenReader)
    }

    /// This capability lets the handle fork into an independent Standalone
    /// writer under a fresh identity. The fork replaces `main.db`, so it
    /// takes the writer sentinel with no other frozen reader present. Only a
    /// handle holding the frozen-reader or writer sentinel on a
    /// non-Standalone store can make that trade.
    #[must_use]
    pub(crate) const fn forks_into_writer(self) -> bool {
        matches!(
            self.long_lived_lock,
            LongLivedLock::FrozenReader | LongLivedLock::Writer
        ) && !matches!(self.recovery_authority, RecoveryAuthority::Standalone)
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
    pub(crate) const fn open_capabilities(self) -> DbModeCapabilities {
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
    /// Turn away an operation this handle's mode does not authorize.
    ///
    /// `authorized` is read off the one capability matrix rather than from a
    /// `matches!` at the call site, and `required` is the mode the embedder is
    /// told to reopen or promote into. Every mode gate in the crate goes
    /// through here, so "wrong mode" is a single variant an embedder can match
    /// once instead of six method-specific spellings.
    pub(crate) fn require_mode(
        &self,
        operation: &'static str,
        required: DbMode,
        authorized: impl FnOnce(DbModeCapabilities) -> bool,
    ) -> Result<()> {
        if authorized(self.mode.open_capabilities()) {
            Ok(())
        } else {
            Err(PagedbError::wrong_mode(operation, required, self.mode))
        }
    }

    /// Open a database in Standalone mode, creating it if `vfs` holds none.
    ///
    /// The bootstrap-versus-reopen decision is made here, under the writer
    /// sentinel, from what is actually on disk — so two processes racing a
    /// first open cannot both bootstrap. `options.cipher` selects the cipher
    /// for a store this call creates and is ignored for one it finds.
    pub async fn open(
        vfs: V,
        kek: impl Into<SecretKey>,
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        let kek = kek.into();
        let db = Self::open_with_mode(
            vfs,
            kek,
            None,
            page_size,
            realm,
            options,
            DbMode::Standalone,
        )
        .await?;
        // Black box: mark the epoch boundary — freed-page use-after-free
        // surfaces on reopen, so the trail needs to know when one happened.
        crate::diag::reopened(db.latest_commit().0);
        Ok(db)
    }

    /// Open a frozen-snapshot database without write access.
    pub async fn open_read_only(
        vfs: V,
        kek: impl Into<SecretKey>,
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        let kek = kek.into();
        Self::open_with_mode(vfs, kek, None, page_size, realm, options, DbMode::ReadOnly).await
    }

    /// Open a best-effort read-only view of a database that may have a writer.
    pub async fn open_observer(
        vfs: V,
        kek: impl Into<SecretKey>,
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
    ) -> Result<Self> {
        let kek = kek.into();
        Self::open_with_mode(vfs, kek, None, page_size, realm, options, DbMode::Observer).await
    }

    /// The one path every public open takes. It applies the mode's sentinel,
    /// the missing-store rule, and bootstrap under the acquisition lock. It
    /// then hands off to the shared existing-store opener, which applies the
    /// rest.
    ///
    /// `counterpart_kek` resumes an interrupted KEK-changing rekey. Such an
    /// open never bootstraps: with no store there is no rekey to resume.
    pub(super) async fn open_with_mode(
        vfs: V,
        kek: SecretKey,
        counterpart_kek: Option<SecretKey>,
        page_size: usize,
        realm: RealmId,
        options: OpenOptions,
        mode: DbMode,
    ) -> Result<Self> {
        // Refuse a clock-dependent policy on a build with no clock, before
        // anything is opened or touched; see
        // `PagedbError::RetainPolicyNeedsClock`.
        check_policy_needs_clock(
            &options.commit_history_retain,
            crate::clock::clock_available(),
        )?;

        let capabilities = mode.open_capabilities();
        let bootstraps = capabilities.bootstraps() && counterpart_kek.is_none();
        let mut locks = Vec::new();

        // A missing database is a terminal error unless the open bootstraps.
        // Probe before acquiring a lock: native lock backends materialize
        // sentinel files when locking an empty directory.
        if !bootstraps && !main_db_exists(&vfs).await? {
            return Err(PagedbError::NotFound);
        }

        let acquisition = vfs.lock_exclusive(ACQUISITION_LOCK_PATH).await?;
        let main_db_exists = {
            let exists = main_db_exists(&vfs).await?;
            if !exists && !bootstraps {
                return Err(PagedbError::NotFound);
            }
            acquire_interlocking_mode_lock(&vfs, capabilities, &mut locks).await?;
            let lock_path = match capabilities.long_lived_lock() {
                LongLivedLock::Writer => WRITER_LOCK_PATH,
                LongLivedLock::FrozenReader => FROZEN_READERS_LOCK_PATH,
                LongLivedLock::Observer => OBSERVERS_LOCK_PATH,
            };
            crate::diag::lock_acquired(&format!("{mode:?}"), lock_path);
            drop(acquisition);
            exists
        };

        let mut db = if main_db_exists {
            Self::open_existing_inner_with_counterpart(
                vfs,
                kek,
                counterpart_kek,
                page_size,
                realm,
                options,
                mode,
            )
            .await?
        } else {
            // The caller already holds the writer sentinel acquired above, so
            // bootstrap through the lock-free inner path rather than
            // `open_internal_with_options`, which would try to reacquire it.
            let cipher = options.cipher;
            Self::open_internal_with_options_and_cipher_unlocked(
                vfs, kek, page_size, realm, options, cipher,
            )
            .await?
        };
        db.mode = mode;
        db.sentinel_locks = locks;
        // Only writer modes (Standalone/Follower) are ever expected to reach
        // the commit path this flag guards; ReadOnly/Observer hold a
        // different sentinel kind and never write.
        db.lock_required = capabilities.allows_user_writes();
        Ok(db)
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

pub(super) async fn acquire_interlocking_mode_lock<V: Vfs>(
    vfs: &V,
    capabilities: DbModeCapabilities,
    locks: &mut Vec<V::LockHandle>,
) -> Result<()> {
    match capabilities.long_lived_lock() {
        LongLivedLock::Writer => {
            let frozen_probe =
                vfs.lock_exclusive(FROZEN_READERS_LOCK_PATH)
                    .await
                    .map_err(|error| {
                        map_lock_contention(error, || {
                            crate::diag::lock_rejected(
                                "writer",
                                FROZEN_READERS_LOCK_PATH,
                                "readers_present",
                            );
                            PagedbError::ReadersPresent
                        })
                    })?;
            drop(frozen_probe);
            acquire_long_lived_lock(vfs, LongLivedLock::Writer, locks).await
        }
        LongLivedLock::FrozenReader => {
            let writer_probe = vfs
                .lock_exclusive(WRITER_LOCK_PATH)
                .await
                .map_err(|error| {
                    map_lock_contention(error, || {
                        crate::diag::lock_rejected(
                            "frozen_reader",
                            WRITER_LOCK_PATH,
                            "writer_present",
                        );
                        PagedbError::WriterPresent
                    })
                })?;
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
            .map_err(|error| {
                map_lock_contention(error, || {
                    crate::diag::lock_rejected("writer", WRITER_LOCK_PATH, "already_open");
                    PagedbError::AlreadyOpen
                })
            })?,
        LongLivedLock::FrozenReader => {
            vfs.lock_shared(FROZEN_READERS_LOCK_PATH)
                .await
                .map_err(|error| {
                    map_lock_contention(error, || {
                        crate::diag::lock_rejected(
                            "frozen_reader",
                            FROZEN_READERS_LOCK_PATH,
                            "already_locked",
                        );
                        PagedbError::AlreadyLocked
                    })
                })?
        }
        LongLivedLock::Observer => vfs
            .lock_shared(OBSERVERS_LOCK_PATH)
            .await
            .map_err(|error| {
                map_lock_contention(error, || {
                    crate::diag::lock_rejected("observer", OBSERVERS_LOCK_PATH, "already_locked");
                    PagedbError::AlreadyLocked
                })
            })?,
    };
    locks.push(handle);
    Ok(())
}

pub(super) fn map_lock_contention(
    error: PagedbError,
    on_contention: impl FnOnce() -> PagedbError,
) -> PagedbError {
    if matches!(error, PagedbError::AlreadyLocked) {
        on_contention()
    } else {
        error
    }
}

/// Refuse a retention policy that cannot work without a wall clock.
///
/// `RetainPolicy::Age` decides what to prune by comparing each entry's recorded
/// timestamp against `now - duration`. On a build with no clock there is no
/// `now`: a stand-in zero makes every threshold zero, so no entry is ever older
/// than it, the prune walk ends at its first row, and the policy behaves as
/// `Unbounded` while still reporting itself as age-based — an unbounded history
/// nobody asked for, and nothing in the API says so.
///
/// `Unbounded` prunes nothing by definition, `Count` prunes by ordinal, and
/// `Disabled` keeps no history index at all, so none of the three consults time
/// and none is refused. Taking `clock_available` as a parameter rather than
/// reading it here is what makes both branches testable on a target that has a
/// clock.
pub(crate) fn check_policy_needs_clock(
    policy: &crate::options::RetainPolicy,
    clock_available: bool,
) -> Result<()> {
    if let crate::options::RetainPolicy::Age(_) = policy
        && !clock_available
    {
        return Err(PagedbError::RetainPolicyNeedsClock { policy: "Age" });
    }
    Ok(())
}

#[cfg(test)]
mod policy_clock_tests {
    use super::check_policy_needs_clock;
    use crate::options::RetainPolicy;
    use crate::{PagedbError, Result};
    use std::time::Duration;

    /// The defect this guards: without a clock, age retention must be refused
    /// rather than run against a zero threshold and silently prune nothing.
    #[test]
    fn age_is_refused_when_the_build_has_no_clock() {
        let refused: Result<()> =
            check_policy_needs_clock(&RetainPolicy::Age(Duration::from_secs(60)), false);
        assert!(
            matches!(
                refused,
                Err(PagedbError::RetainPolicyNeedsClock { policy: "Age" })
            ),
            "age retention must be refused by name when no clock exists"
        );
    }

    /// With a clock it is served, so the refusal cannot be a blanket one.
    #[test]
    fn age_is_served_when_the_build_has_a_clock() {
        assert!(
            check_policy_needs_clock(&RetainPolicy::Age(Duration::from_secs(60)), true).is_ok()
        );
    }

    /// `Unbounded` never prunes, `Count` prunes by ordinal, and `Disabled`
    /// keeps no history index, so none reads the clock and none may be caught
    /// by this check.
    #[test]
    fn clock_free_policies_are_never_refused() {
        for policy in [
            RetainPolicy::Unbounded,
            RetainPolicy::Count(4),
            RetainPolicy::Disabled,
        ] {
            assert!(
                check_policy_needs_clock(&policy, false).is_ok(),
                "consults no clock and must open without one"
            );
            assert!(check_policy_needs_clock(&policy, true).is_ok());
        }
    }
}
