//! Publish a sealed scratch image by renaming it over `main.db`.

use std::sync::atomic::Ordering;

use crate::catalog::codec::RekeyIntent;
use crate::crypto::{DerivedKey, MasterKey};
use crate::errors::PagedbError;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::ActiveSlot;
#[cfg(test)]
use crate::txn::db::core::RekeyTestFault;
use crate::txn::db::{Db, WriterState};
use crate::vfs::Vfs;
use crate::{CommitId, Result};

use super::seal::ScratchImage;

/// Rename attempts while a reader in flight still holds the old `main.db` open.
const RENAME_ATTEMPTS: u32 = 8;

/// A backend that cannot replace an open file reports one of these. Windows and
/// OPFS can refuse while a read holds its handle for a moment. The OPFS backend
/// reports a held handle as `ReadOnly`, and no backend reports a rename that way
/// for any other reason.
fn rename_can_succeed_on_retry(error: &PagedbError) -> bool {
    match error {
        PagedbError::ReadOnly => true,
        PagedbError::Io(io_error) => matches!(
            io_error.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ResourceBusy
        ),
        _ => false,
    }
}

/// The keys the swap makes live.
pub(super) struct TargetKeys<'a> {
    pub master: &'a MasterKey,
    pub header: &'a DerivedKey,
}

impl<V: Vfs + Clone> Db<V> {
    /// Replace `main.db` with `scratch`.
    ///
    /// Compaction refuses to run beside a registered reader. A rekey does not, so
    /// a read can reopen the old file in the window before the rename. Each attempt
    /// therefore closes the cached handle first.
    async fn rename_scratch_over_main(&self, scratch: &str) -> Result<()> {
        let mut attempt = 1;
        loop {
            self.pager.close_main_handle().await;
            match self.vfs.rename(scratch, &self.main_db_path).await {
                Ok(()) => return Ok(()),
                Err(error) if attempt < RENAME_ATTEMPTS && rename_can_succeed_on_retry(&error) => {
                    attempt += 1;
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Rename `scratch` over `main.db` and move the handle onto it. The rename is
    /// the atomic commit point of the main image.
    ///
    /// Before it, the old `main.db` stands whole. After it, the store continues
    /// from the scratch's own header and intent.
    ///
    /// The target epoch activates here and nowhere else, right after the rename
    /// returns, with this guard armed since before the rename and the visibility
    /// gate held. So no seal outside the rebuild ever runs under the target key
    /// behind a source header. A drop at the gate changes nothing, and the handle
    /// stays usable.
    ///
    /// A pinned reader keeps working across this. Its page ids and their logical
    /// content are the same in both files. A read that lands on the new file finds
    /// the target key, which the keyring holds from immediately before the
    /// rename. A read that fetched from the old file is not cached, by the
    /// handle generation. A
    /// page guard holds its own copy of the plaintext, and the cache reset spares
    /// a pinned entry. The keyring keeps the source key until the last such reader
    /// leaves.
    ///
    /// A backend can finish the rename after its future is dropped, or after it
    /// reports an error, so every return that skips the disarm poisons the handle.
    /// Only a reopen can read which file won.
    pub(super) async fn swap_scratch_over_main(
        &self,
        state: &mut WriterState,
        scratch: &str,
        image: &ScratchImage,
        intent: &RekeyIntent,
        keys: TargetKeys<'_>,
    ) -> Result<()> {
        let commit = CommitId(state.latest_commit_id);
        let unpublished = || {
            PagedbError::rekey_target_epoch_activated(
                commit,
                PagedbError::durably_committed_but_unpublished(commit),
            )
        };
        #[cfg(test)]
        self.notify_writer_waiting();
        let visibility = self.visibility_gate.write().await;
        let publish = self.arm_durable_publish(commit);
        self.pager
            .install_mk_epoch(keys.master.clone(), intent.target_mk_epoch, self.cipher_id);
        if let Err(error) = self.rename_scratch_over_main(scratch).await {
            tracing::error!(%error, "rekey rename failed, so the file it left is unknown");
            return Err(unpublished());
        }

        self.pager
            .set_active_mk_epoch(keys.master.clone(), intent.target_mk_epoch);
        *self.hk.write() = keys.header.clone();
        self.mk_epoch
            .store(intent.target_mk_epoch, Ordering::SeqCst);
        // Slot A of the scratch is the only verifiable header of this file. Anchor
        // refreshes the rebuild wrote into the replaced file went with it, and this
        // header's anchor covers what they did.
        self.pager.note_header_written(HeaderCursor {
            slot: ActiveSlot::A,
            seq: image.header_seq,
        });
        state.catalog_root_page_id = image.catalog_root_page_id;
        state.next_page_id = image.next_page_id;
        state.free_list_root_page_id = image.free_list_root_page_id;
        state.free_list_entries = image.free_list_entries;
        #[cfg(test)]
        {
            if let Err(error) = self.interrupt_rekey_if_requested(RekeyTestFault::MainFileRenamed) {
                return Err(PagedbError::rekey_target_epoch_activated(commit, error));
            }
        }

        // A read in the window before the rename can reopen the old file. This
        // close drops that handle, and the reset drops what it cached.
        self.pager.close_main_handle().await;
        if self.pager.reset_main_pages().is_err() {
            return Err(unpublished());
        }
        if self.vfs.sync_dir(self.main_db_parent_dir()).await.is_err() {
            return Err(unpublished());
        }
        let _ = self
            .finish_durable_commit_visible(&visibility, state, commit, image.counter_anchor, &[])
            .await
            .map_err(|error| PagedbError::rekey_target_epoch_activated(commit, error))?;
        publish.disarm();
        Ok(())
    }
}
