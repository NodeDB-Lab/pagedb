//! Drive one rebuild of `main.db`: scratch, seal, rename.
//!
//! The live `main.db` keeps its only intact copy of every page until the rename.
//! A crash before the rename leaves the old file whole, plus a scratch the next
//! open removes. That open then starts the rebuild over from the durable intent.
//! A crash after the rename continues from the scratch's own header and intent.
//!
//! The scratch has the same page ids as the live file. Free pages below the
//! reclamation floor are blank. Pages no root, retained row, or free list names
//! are not copied, so they read as zeros, and the file ends at the cursor. A page
//! left under the source key by a crash or a leak does not survive the rename.
//!
//! Every scratch page seals under the target epoch and key the rebuild carries in
//! its [`RebuildImage`]. The pager's active epoch stays on the epoch the live header
//! names until the rename, so an ordinary seal never sees the target key.
//!
//! Cost: free space up to the size of `main.db`, from the first scratch write to
//! the rename. A sparse scratch uses less when the live file holds unnamed pages.

use crate::Result;
use crate::catalog::codec::{RekeyIntent, RekeyStage};
use crate::crypto::{DerivedKey, MasterKey};
use crate::errors::PagedbError;
use crate::pager::core::RebuildImage;
#[cfg(test)]
use crate::txn::db::core::RekeyTestFault;
use crate::txn::db::{Db, WriterState};
use crate::vfs::{Vfs, remove_if_present};

use super::seal::ScratchImage;
use super::swap::TargetKeys;

/// Whether a durable intent at `stage` still needs a rebuild.
///
/// A store at a later stage has its target-key `main.db` already. A file from an
/// earlier release can sit at any of the earlier stages, with both keys in it.
pub(in crate::txn::db::rekey) fn stage_needs_rebuild(stage: RekeyStage) -> bool {
    matches!(
        stage,
        RekeyStage::Intent
            | RekeyStage::MainPagesTargetReadable
            | RekeyStage::HeaderTargetPublished
    )
}

/// A one-shot test interruption models a crash, so its scratch stays on disk.
#[cfg(test)]
fn is_test_interruption(error: &PagedbError) -> bool {
    matches!(error, PagedbError::Io(io_error) if io_error.to_string() == "rekey test interruption")
}

impl<V: Vfs + Clone> Db<V> {
    /// Rebuild `main.db` under the target key and publish it by rename. On `Ok`,
    /// `intent` and `state` describe the new file, at stage `MainDone`.
    ///
    /// A caller can drop this future at any await. Before the rename, the guard
    /// drops the scratch pages from the cache. The handle stays usable, because
    /// `state`, the header, the flush epoch, and the keyring still describe the
    /// untouched live file. The scratch stays until the next rebuild or open. From
    /// the rename on, the guard in `swap_scratch_over_main` poisons the handle.
    pub(in crate::txn::db::rekey) async fn rebuild_main_under_target_key(
        &self,
        state: &mut WriterState,
        intent: &mut RekeyIntent,
        target_master_key: &MasterKey,
        target_header_key: &DerivedKey,
    ) -> Result<()> {
        let scratch = format!("{}.rekey", self.main_db_path);
        remove_if_present(&*self.vfs, &scratch).await?;
        let image = self.pager.rebuild_image(
            self.realm_id,
            scratch.clone(),
            intent.target_mk_epoch,
            target_master_key,
        )?;

        // Scratch pages sit in the cache under ids the live image also uses. A dirty
        // one must never reach the live file, and a blank one must never answer a
        // read once this future ends without a rename.
        let unpublished = self.discard_unpublished_pages_on_drop();
        match self
            .build_scratch_image(state, intent, &scratch, &image, target_header_key)
            .await
        {
            Ok(sealed) => {
                let keys = TargetKeys {
                    master: target_master_key,
                    header: target_header_key,
                };
                let outcome = self
                    .swap_scratch_over_main(state, &scratch, &sealed, intent, keys)
                    .await;
                // The swap either reset the cache itself or poisoned the handle.
                unpublished.disarm();
                outcome?;
                intent.stage = RekeyStage::MainDone;
                Ok(())
            }
            Err(error) => {
                drop(unpublished);
                Err(self.abandon_scratch(&scratch, intent, error).await)
            }
        }
    }

    /// Build a complete `main.db` in `scratch`. `state` and the live file stay as
    /// they are, except that a long run of seals can refresh the live header's
    /// anchor. A refresh publishes nothing.
    async fn build_scratch_image(
        &self,
        state: &WriterState,
        intent: &RekeyIntent,
        scratch: &str,
        image: &RebuildImage,
        target_header_key: &DerivedKey,
    ) -> Result<ScratchImage> {
        self.size_scratch(scratch, state.next_page_id).await?;
        let named = self.reseal_named_pages_to(state, image).await?;
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::MainPagesTargetReadable)?;
        let sealed = self
            .seal_scratch_image(state, intent, &named, scratch, image, target_header_key)
            .await?;
        #[cfg(test)]
        self.interrupt_rekey_if_requested(RekeyTestFault::HeaderTargetPublished)?;
        Ok(sealed)
    }

    /// Remove the scratch of a failed rebuild and return the error to report. A
    /// full device becomes an error that says the store is intact and what to do.
    async fn abandon_scratch(
        &self,
        scratch: &str,
        intent: &RekeyIntent,
        error: PagedbError,
    ) -> PagedbError {
        #[cfg(test)]
        {
            if is_test_interruption(&error) {
                return error;
            }
        }
        if let Err(remove_error) = remove_if_present(&*self.vfs, scratch).await {
            tracing::warn!(
                %remove_error,
                "rekey scratch stayed on disk, and the next open removes it"
            );
        }
        match error {
            PagedbError::NoSpace => {
                PagedbError::rekey_no_space(intent.source_mk_epoch, intent.target_mk_epoch)
            }
            other => other,
        }
    }
}
