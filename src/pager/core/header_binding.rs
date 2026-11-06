//! Live header binding and nonce anchor methods.

use std::sync::Arc;

use super::pager::Pager;
use crate::Result;
use crate::errors::PagedbError;
#[cfg(test)]
use crate::pager::anchor::AnchorTestFault;
use crate::pager::anchor::{HeaderCursor, LiveHeader, refresh_anchor};
use crate::vfs::Vfs;

impl<V: Vfs> Pager<V> {
    /// Snapshot of the anchor the header writer should persist next.
    pub fn pending_anchor(&self) -> u64 {
        self.main_nonce.lock().pending_anchor()
    }

    /// Tell the Pager that the supplied anchor has been durably persisted to
    /// the A/B header. Future nonces will be issued in `(persisted_anchor,
    /// persisted_anchor + budget]`.
    pub fn commit_anchor(&self, persisted: u64) -> Result<()> {
        #[cfg(test)]
        self.interrupt_anchor_if_requested(AnchorTestFault::Commit)?;
        self.main_nonce.lock().commit_anchor(persisted)
    }

    /// Arm a one-shot interruption of the anchor path. Consumed by the first
    /// matching check; a mismatched point is left armed.
    #[cfg(test)]
    pub(crate) fn interrupt_anchor_after(&self, point: AnchorTestFault) {
        *self.anchor_test_fault.lock() = Some(point);
    }

    #[cfg(test)]
    fn interrupt_anchor_if_requested(&self, point: AnchorTestFault) -> Result<()> {
        let mut fault = self.anchor_test_fault.lock();
        if *fault == Some(point) {
            *fault = None;
            return Err(PagedbError::Io(std::io::Error::other(
                "anchor test interruption",
            )));
        }
        Ok(())
    }

    /// Bind the live `main.db` header to this pager: the key its A/B slots are
    /// MAC'd under, and which slot is currently authoritative.
    ///
    /// Called once by each writable `Db` constructor. Until it is called the
    /// pager cannot refresh the nonce anchor on its own, and a long run of
    /// nonces fails at the budget exactly as it did before.
    pub(crate) fn bind_live_header(
        &self,
        hk: Arc<parking_lot::RwLock<crate::crypto::keys::DerivedKey>>,
        cursor: HeaderCursor,
    ) {
        *self.live_header.lock() = Some(LiveHeader { hk, cursor });
    }

    /// The slot and sequence the next `main.db` header write must use.
    ///
    /// Every writer path takes its A/B slot from here rather than from its own
    /// state, because an anchor refresh can have moved the cursor since the last
    /// commit without changing anything a commit would notice.
    pub(crate) fn header_cursor(&self) -> Result<HeaderCursor> {
        self.live_header
            .lock()
            .as_ref()
            .map(|live| live.cursor)
            .ok_or_else(|| PagedbError::structural_header_invalid("main.db", "header_cursor"))
    }

    /// Record a header this writer just made durable, so the next write — by a
    /// commit or by an anchor refresh — targets the other slot.
    pub(crate) fn note_header_written(&self, cursor: HeaderCursor) {
        let mut live_header = self.live_header.lock();
        if let Some(live) = live_header.as_mut() {
            live.cursor = cursor;
        }
    }

    /// How many more main.db nonces can be issued before the durable anchor has
    /// to be advanced.
    pub(crate) fn main_anchor_window(&self) -> u64 {
        self.main_nonce.lock().window_remaining()
    }

    /// The anchor value currently recorded in the durable header. Tests assert
    /// on it to prove an operation advanced the anchor as it ran, rather than
    /// merely fitting inside a wider window.
    #[cfg(test)]
    pub(crate) fn durable_anchor(&self) -> u64 {
        self.main_nonce.lock().durable_anchor()
    }

    /// Make the nonces issued so far durable by writing them into the live
    /// header, changing nothing else, and reopen the issuing window.
    ///
    /// Safe to call at any point in any operation: the header written here names
    /// exactly the state that was already durable, so it publishes nothing and a
    /// crash straight afterwards reopens at the same commit. See
    /// [`crate::pager::anchor`] for the full argument.
    pub(crate) async fn refresh_main_anchor(&self) -> Result<()> {
        let binding = {
            let live_header = self.live_header.lock();
            live_header
                .as_ref()
                .map(|live| (live.hk.clone(), live.cursor))
        };
        let Some((hk_handle, cursor)) = binding else {
            // No live header bound: the caller is a read-only view, which has no
            // business issuing main.db nonces at all. Report the same exhaustion
            // the nonce generator would.
            return Err(PagedbError::Aborted);
        };
        let anchor = self.main_nonce.lock().pending_anchor();
        // Clone out of the lock: a rekey may swap the header key, and no
        // `parking_lot` guard may cross the header write's awaits.
        let hk = hk_handle.read().clone();
        let next = refresh_anchor(
            &self.vfs,
            &self.cfg.main_db_path,
            &hk,
            cursor,
            anchor,
            self.cfg.page_size,
        )
        .await?;
        #[cfg(test)]
        self.interrupt_anchor_if_requested(AnchorTestFault::RefreshAfterHeader)?;
        // Only now is the anchor durable, so only now may the generator issue
        // past it. A crash before this point leaves the old anchor authoritative
        // and no nonce beyond it was ever issued.
        self.main_nonce.lock().commit_anchor(anchor)?;
        self.note_header_written(next);
        Ok(())
    }

    /// Replace the main.db nonce generator with one recovered from a
    /// persisted anchor. Called by `Db::open_existing` after reading the
    /// header.
    ///
    /// The open writes no header, so the recovered window starts empty. The first
    /// flush after an open persists the anchor before it seals a page.
    pub fn recover_main_nonce(&self, recovered_anchor: u64) {
        let mut g = self.main_nonce.lock();
        *g = crate::crypto::nonce::MainDbNonceGen::recover(
            &self.cfg.main_db_file_id,
            recovered_anchor,
            self.cfg.anchor_budget,
        );
    }

    /// Seal every later `main.db` page of this handle under a fresh random prefix.
    ///
    /// A handle calls this when it becomes a Follower, before it seals any page.
    /// The key, `file_identity`, counter, and anchor stay as they are.
    pub(crate) fn use_local_nonce_prefix(&self) -> Result<()> {
        let prefix = crate::crypto::random::local_nonce_prefix(&self.cfg.main_db_file_id)?;
        self.main_nonce.lock().use_prefix(prefix);
        Ok(())
    }

    /// Issue later nonces under the file prefix, and return the prefix it replaced.
    /// A test uses this to write a page the way a producer's delta carries it.
    #[cfg(test)]
    pub(crate) fn swap_to_file_nonce_prefix(&self) -> [u8; 6] {
        let mut file_prefix = [0u8; 6];
        file_prefix.copy_from_slice(&self.cfg.main_db_file_id[..6]);
        let mut generator = self.main_nonce.lock();
        let replaced = generator.prefix();
        generator.use_prefix(file_prefix);
        replaced
    }

    /// Restore a prefix [`Self::swap_to_file_nonce_prefix`] returned.
    #[cfg(test)]
    pub(crate) fn restore_nonce_prefix(&self, prefix: [u8; 6]) {
        self.main_nonce.lock().use_prefix(prefix);
    }
}
