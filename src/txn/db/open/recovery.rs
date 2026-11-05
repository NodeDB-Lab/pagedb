//! Mode-authorized recovery after authenticated header reconstruction.

use crate::Result;
use crate::crypto::SecretKey;
use crate::pager::freelist;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::{Vfs, remove_if_present};

use super::super::catalog::history_policy::proves_unreadable_pages;
use super::super::core::Db;

pub(super) async fn recover_open_state<V: Vfs + Clone>(
    db: &Db<V>,
    primary_kek: &SecretKey,
    counterpart_kek: Option<&SecretKey>,
    fields: &MainDbHeaderFields,
) -> Result<()> {
    let capabilities = db.mode.open_capabilities();
    let rekey_in_flight = db
        .admit_rekey_recovery(primary_kek, counterpart_kek)
        .await?;

    if fields.apply_journal_root_page_id != 0 || fields.apply_journal_root_version != 0 {
        if !capabilities.applies_interrupted_apply() {
            return Err(crate::errors::PagedbError::Unsupported);
        }
        db.retry_pending_apply_journal().await?;
    }

    if capabilities.runs_standalone_recovery() {
        // Compaction and `rekey_into_writer` each build a replacement
        // `main.db` beside the live one and publish it by rename. A scratch
        // still present at open is one whose rename never happened.
        for suffix in [".compact", ".fork"] {
            remove_if_present(&*db.vfs, &format!("{}{suffix}", db.main_db_path)).await?;
        }

        // A fork's segments wait outside the orphan scan until its `main.db`
        // is live. This open has write authority over that `main.db`, so it
        // hands them to the catalog repair below.
        crate::recovery::fork::adopt_forked_segments(&*db.vfs).await?;

        // Write-transaction spill scratch is keyed to the handle that wrote it,
        // so anything still present belongs to a handle that is gone and is
        // reclaimable outright. Without this the scratch of every transaction
        // that died with its process would accumulate for the life of the
        // store. Gated with the removals above because it needs write
        // authority.
        crate::recovery::scratch::delete_orphaned_scratch(&*db.vfs).await?;

        // Same reasoning for retired segments. A tombstone is only reachable by
        // a reader that pinned it before the retirement, and no such reader can
        // survive the process that opened it — so anything still parked here at
        // open belongs to a handle that is gone. Without this, a crash between
        // retiring a segment and reclaiming it leaked that file permanently, and
        // stores carried the residue of every crash they had ever had.
        match crate::recovery::gc::delete_tombstone_files(&*db.vfs).await {
            Ok((0, _)) => {}
            Ok((count, bytes)) => tracing::info!(
                reclaimed_segments = count,
                reclaimed_bytes = bytes,
                "open: reclaimed tombstoned segments left by a previous run"
            ),
            // The store is usable without this; failing the open over unreclaimed
            // garbage would turn a disk-space problem into an availability one.
            Err(error) => tracing::warn!(
                %error,
                "open: could not reclaim tombstoned segments; they remain on disk"
            ),
        }
    }

    // An incremental apply assembles its target beside `main.db` and renames it
    // in. A scratch that outlived its apply is an apply that never reached that
    // rename, so the live file is authoritative and the scratch is a full-size
    // copy of a state nothing names. Removing it needs write authority, which
    // is why it is gated rather than done unconditionally.
    #[cfg(not(target_arch = "wasm32"))]
    {
        if capabilities.applies_interrupted_apply() {
            let staged = crate::snapshot::apply::staged_image_path(&db.main_db_path);
            remove_if_present(&*db.vfs, &staged).await?;
        }
    }

    if rekey_in_flight {
        if !capabilities.runs_standalone_recovery() {
            return Err(crate::errors::PagedbError::Unsupported);
        }
        db.resume_rekey_intent().await?;
    }

    let (catalog_root_page_id, next_page_id) = {
        let state = db.writer.lock().await;
        (state.catalog_root_page_id, state.next_page_id)
    };
    let recovery_commit = db.latest_commit().0;
    if capabilities.runs_standalone_recovery() {
        crate::recovery::repair_catalog(
            &*db.vfs,
            db.pager.clone(),
            db.realm_id,
            catalog_root_page_id,
            next_page_id,
            db.page_size,
            db.file_id,
            recovery_commit,
        )
        .await?;
    } else {
        crate::recovery::verify_catalog(
            &*db.vfs,
            db.pager.clone(),
            db.realm_id,
            catalog_root_page_id,
            next_page_id,
            db.page_size,
            db.file_id,
            recovery_commit,
        )
        .await?;
    }

    db.validate_counter_rows(catalog_root_page_id, next_page_id)
        .await?;

    if capabilities.runs_standalone_recovery() {
        db.drop_unreadable_free_list().await;
    }

    db.publish_free_list_count().await;

    Ok(())
}

impl<V: Vfs + Clone> Db<V> {
    /// Count the settled free-list chain and publish the count, so `stats` never
    /// reads the chain on a healthy store.
    ///
    /// This costs one page read. A read error leaves the count unknown and never
    /// fails the open. A free list records reclaimable space and holds no data.
    async fn publish_free_list_count(&self) {
        let mut state = self.writer.lock().await;
        let entries =
            match freelist::count_chain(&self.pager, self.realm_id, state.free_list_root_page_id)
                .await
            {
                Ok(entries) => Some(entries),
                Err(error) => {
                    tracing::warn!(
                        free_list_root = state.free_list_root_page_id,
                        %error,
                        "free-list head read failed at open; stats reads it on demand"
                    );
                    None
                }
            };
        state.free_list_entries = entries;
        self.snapshot.write().free_list_entries = entries;
    }

    /// Detach the free-list chain when it cannot be read, so a store with a
    /// damaged chain still opens.
    ///
    /// A free list records reclaimable space, not data: every page it names is
    /// already unreachable from every root. Losing it therefore costs only the
    /// ability to reuse that space — those pages become leaked, and a full
    /// compaction reclaims them by rebuilding the file. Nothing reachable
    /// through the roots is affected.
    ///
    /// Treating an unreadable chain as fatal traded that bounded, recoverable
    /// cost for an unbounded one: the store would not open at all, so one
    /// damaged page in a store of hundreds of thousands put every record in it
    /// out of reach.
    ///
    /// The chain is dropped in memory only. Every commit writes the free-list
    /// root into the header, so the next one persists the detachment; a crash
    /// before then leaves the same unreadable chain to be dropped again on the
    /// following open, which is why repeating this is safe.
    ///
    /// Rebuilding the free set instead — walking the roots and treating every
    /// unreachable page as free — is deliberately NOT done here. It would
    /// recover the space, but a reachability computation that errs in the unsafe
    /// direction hands a live page to a second owner, which is silent data
    /// corruption rather than a leak. Compaction already reclaims that space
    /// through a path whose correctness does not rest on the inference.
    ///
    /// This lives beside its caller rather than with the free-list rebuild used
    /// by incremental apply: that path is native-only, this one runs on every
    /// target a store can be opened from. A browser-hosted store damages its
    /// chain the same way a native one does, and skipping the detach there
    /// would leave it unopenable for the same reason this recovery exists.
    pub(crate) async fn drop_unreadable_free_list(&self) {
        let head = {
            let state = self.writer.lock().await;
            state.free_list_root_page_id
        };
        if head == 0 {
            return;
        }

        let mut walk = freelist::ChainWalk::new(head);
        let error = loop {
            match walk.advance(&self.pager, self.realm_id).await {
                Ok(Some(_)) => {}
                Ok(None) => return,
                // Proof about the chain's bytes only. A transient I/O failure says
                // nothing about its content, and detaching on one leaks every
                // page it names because a disk hiccuped during startup.
                Err(error) if proves_unreadable_pages(&error) => break error,
                Err(error) => {
                    tracing::warn!(
                        free_list_root = head,
                        %error,
                        "free-list chain could not be read at open; leaving it attached, \
                         since this reports an I/O failure rather than damaged content"
                    );
                    return;
                }
            }
        };

        tracing::error!(
            free_list_root = head,
            %error,
            "free-list chain is unreadable; detaching it so the store opens. The pages it \
             named are unreachable from every root, so no data is lost — the space they \
             occupy is leaked until a full compaction rebuilds the file."
        );
        let mut state = self.writer.lock().await;
        state.free_list_root_page_id = 0;
    }
}
