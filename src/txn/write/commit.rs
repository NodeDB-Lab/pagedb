//! `WriteTxn::commit` — flush dirty pages, rewrite the durable free-list,
//! write the A/B header, apply pending segment side effects, and publish the
//! new root to readers.
//!
//! ## Free-page reclamation
//!
//! A B+ tree commit copies-on-write every modified leaf and its spine, freeing
//! the old pages. The set of free pages lives in a durable chain rooted at the
//! header's `free_list_root` (see [`crate::pager::freelist`]) — outside the
//! catalog tree, so maintaining it adds no catalog churn and survives an
//! unclean shutdown.
//!
//! Each commit, after materializing all three trees, rewrites the bounded
//! *window* of the chain that `begin` scanned: `(window entries) − (pages
//! reused this commit) + (pages freed this commit) + (the window's own pages)`.
//! The fresh pages are spliced onto the retained tail — the part of the chain
//! the window did not reach, which is left byte-for-byte alone because every
//! chain page carries its own `next` and count and the header publishes only
//! the head. Both the memory the rewrite holds and the pages it writes are
//! therefore capped by the scan budget rather than by how many pages are free.
//!
//! Every entry is tagged with the commit that freed it; `begin` recycles only
//! those below the reclamation floor (observable by no reader and no
//! retained-history root). The chain is committed atomically with the header
//! swap, so no freed page is ever lost as an orphan, and a page is recycled
//! only after the commit that overwrote it is durable.
//!
//! The window rewrite trades a global view for a bounded one, so the
//! duplicate-safety that came free from rebuilding the whole chain has to be
//! stated as a rule instead: a page may enter the allocator cache only from the
//! scanned window, and this commit deletes it from that window. An id fed to
//! the allocator from anywhere else would still be named by the untouched tail.
//!
//! Crash-safety of the rewrite: new chain pages are drawn only from pages that
//! were *already free* before this commit (or freshly bump-allocated) — never
//! from pages this commit freed (still live under the old root until the swap),
//! nor from the window's own pages (must stay readable until the swap), nor
//! from the retained tail (never superseded at all). On a crash before the
//! header swap, the old `free_list_root` and everything it references are
//! intact.

use crate::errors::PagedbError;
use crate::pager::anchor::HeaderCursor;
use crate::pager::freelist;
use crate::pager::freelist::CHAIN_METADATA_CID;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;
use crate::{CommitId, Result};
use std::collections::HashSet;

use super::super::db::{CommitHistoryMeta, PendingWriterState, encode_free_list_root};
use super::txn::WriteTxn;

impl<V: Vfs + Clone> WriteTxn<'_, V> {
    /// Flush dirty pages, write the A/B header, apply pending segment side
    /// effects, and publish the new root to readers. Returns the assigned
    /// `CommitId`.
    pub async fn commit(mut self) -> Result<CommitId> {
        let outcome = self.commit_body().await;
        // The per-transaction spill file and the byte gauge it feeds belong to
        // this transaction whichever way it ended: a refused commit that left
        // `tmp/scratch-<seq>` on disk and the gauge non-zero would be a
        // candidate leaving a trace behind, the same class of bug as an
        // advanced allocation cursor. Cleaned up here, once, so no exit from
        // the body can forget it.
        self.cleanup_spill_async().await;
        self.db
            .spill_bytes_in_use
            .store(0, std::sync::atomic::Ordering::Relaxed);
        outcome
    }

    /// The commit protocol proper. Split from [`Self::commit`] so that every
    /// early return — and every fallible step added between materialization and
    /// the durable header write — passes through one shared cleanup.
    #[allow(clippy::too_many_lines)]
    async fn commit_body(&mut self) -> Result<CommitId> {
        debug_assert!(
            self.db.write_lock_satisfied(),
            "page write without held writer lock"
        );
        let _span = tracing::debug_span!("txn.commit");
        // Note: span is not entered via `.entered()` to keep this async fn's
        // future `Send`. Use `tracing::instrument` or enter in sync sections only.
        let new_commit_id = self.guard.latest_commit_id + 1;
        // Presence of the variable enables the opt-in structural invariant,
        // including a non-Unicode value.
        let invariant_checks = std::env::var_os("PAGEDB_INVARIANT_CHECKS").is_some();
        // A candidate commit that does not become durable must leave no trace
        // in shared state. Everything this function advances before the header
        // write lands here rather than in the shared `WriterState`, and is
        // published only once that header is durable — so every fallible step
        // below (and any added later) can return with nothing to unwind.
        let mut pending = PendingWriterState::capture(&self.guard);

        // ── Materialize all trees first ──────────────────────────────────────
        // Done before accounting freed pages so every copy-on-write spine free
        // (which is realized during the flush, not before it) is captured.
        self.btree.materialize_dirty().await?;
        self.sync_allocator_to_catalog();
        self.catalog_tree.materialize_dirty().await?;
        self.sync_allocator_from_catalog();
        let new_root = self.btree.root_page_id();
        let new_catalog_root = self.catalog_tree.root_page_id();
        pending.next_page_id = self
            .btree
            .next_page_id()
            .max(self.catalog_tree.next_page_id());

        // Commit-history entry (also materialized here). Its frees are never
        // reader-pinned, so they fold into the free-list like any other.
        let unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let history_meta = CommitHistoryMeta {
            active_root_page_id: new_root,
            catalog_root_page_id: new_catalog_root,
            free_list_root_page_id: self.guard.free_list_root_page_id,
            next_page_id: pending.next_page_id,
            unix_seconds,
        };
        let mut hist_freed: Vec<u64> = Vec::new();
        if !matches!(
            self.db.options.commit_history_retain,
            crate::options::RetainPolicy::Disabled
        ) {
            hist_freed = self
                .db
                .write_commit_history_entry(&mut pending, new_commit_id, history_meta)
                .await?;
        }

        // ── Account freed and reused pages ───────────────────────────────────
        // Pages freed by this commit (now live under the *old* root until the
        // header swaps). Reserved pages 0..=3 are header/spare slots.
        let all_freed: Vec<u64> = self
            .btree
            .drain_freed()
            .into_iter()
            .chain(self.catalog_tree.drain_freed())
            .chain(hist_freed)
            .filter(|&pid| pid >= 4)
            .collect();
        // Pages the allocator reused from the cache this txn — they were free
        // before, now hold live committed data, so they leave the free-list.
        // Emptied here rather than mid-session: the trees have all drained, so
        // nothing can still be banking pages against it.
        let consumed = self.db.free_page_consumed.take();

        // The scanned window after this commit: its entries minus the ones
        // reused, kept with their original freeing-commit tag. Every id in
        // `consumed` came from this window (the allocator cache is loaded from
        // nowhere else), so filtering here is what discharges the rule that a
        // recycled page leaves the chain in the same commit that hands it out.
        let prior_free: Vec<(u64, u64)> = std::mem::take(&mut self.free_set_loaded)
            .into_iter()
            .filter(|(_, pid)| !consumed.contains(pid))
            .collect();
        let old_chain: Vec<u64> = std::mem::take(&mut self.old_chain_pages);
        let retained_tail = self.retained_tail;

        // Pages safe to *host* the rewritten chain: only those below the
        // reclamation floor and not reused — i.e. the remaining contents of the
        // allocator cache (loaded at begin with exactly the floor-safe pages).
        // A free-list entry with `cid >= floor` is a page a pinned reader still
        // sees (it was freed *after* that reader's snapshot), so it must never
        // be overwritten — only carried forward as an entry.
        let host_candidates: Vec<u64> = std::mem::take(&mut *self.db.free_page_cache.lock())
            .into_iter()
            .filter(|pid| !consumed.contains(pid))
            .collect();

        // Assemble the new free-list: prior-free pages (kept with their original
        // freeing-commit tag) plus this commit's data-page frees, tagged with
        // this commit so the reclamation floor gates them behind any reader that
        // still sees them.
        let mut entries: Vec<(u64, u64)> = prior_free;
        entries.extend(all_freed.iter().map(|&pid| (new_commit_id, pid)));

        // The superseded window pages are writer-only metadata — NO reader
        // snapshot ever traverses the free-list — so, unlike data-page frees,
        // they must not be floor-gated by pinned readers. Tag them with the
        // sentinel commit `0`, which is below every real reclamation floor (real
        // commit ids start at 1), so the next commit can recycle them regardless
        // of any long-lived reader. This is crash-safe: the in-session reuse
        // threshold (`next_page_id` at begin) already prevents reusing them
        // before this commit's header — the one that supersedes them — is
        // durable. Without this, a pinned reader keeps the old-chain pages
        // un-reclaimable, they re-enter the chain as free entries, and the chain
        // grows by its own size every commit — a feedback loop that eventually
        // makes one commit exceed the per-commit nonce budget and wedges the
        // store (and, short of that, is severe write amplification).
        entries.extend(old_chain.iter().map(|&pid| (CHAIN_METADATA_CID, pid)));

        // The reader-stall policy fires only on entries a live reader is
        // genuinely holding — those at or above the oldest reader pin. Entries
        // below it are being recycled and must not count, or an inherited-but-
        // drainable backlog would spuriously abort a reader on reopen.
        //
        // The pin, and not the reclamation floor: the floor also folds in
        // commit-history retention, and pages retention holds are not pages any
        // reader abort can release. Counting them would abort readers for
        // something no reader did, and would tie the cost of this count — which
        // walks what it reports — to how deep retention runs.
        //
        // Evaluated before the chain write so a reject aborts cleanly: it
        // returns without unwinding because the candidate's advances are held
        // in `pending` and the shared state still describes the durable header.
        //
        // The threshold is defined over the whole chain, which a windowed
        // rewrite cannot produce on its own: `entries` covers only the scanned
        // window. The tail supplies the rest from the summary each of its pages
        // carries — the count stops at the first page whose suffix cannot reach
        // the pin, since nothing below it can be held. With no live reader
        // nothing can be, and that is the first page.
        let tail_stuck = freelist::count_at_or_above_floor(
            &self.db.pager,
            self.db.realm_id,
            retained_tail.head,
            self.reader_floor,
        )
        .await?;
        let window_stuck = entries
            .iter()
            .filter(|(cid, _)| *cid >= self.reader_floor)
            .count() as u64;
        self.db
            .evaluate_stall_policy(tail_stuck.saturating_add(window_stuck))?;

        // Opt-in structural invariant. Run before the free-list rewrite and
        // durable header swap so a violation cannot publish a commit that the
        // caller observes as failed. Check every live tree, including commit
        // history, and keep the strict dangling-pointer walk that detects pages
        // freed in an earlier commit.
        //
        // The freed set is the rewritten window: every page this commit frees,
        // every page it carries forward from the window, and the window's own
        // superseded pages. Entries in the retained tail were already checked by
        // the commit that put them there and are not re-walked, which keeps the
        // check's cost tied to the same budget as the rewrite it guards.
        //
        // No unwind is needed here: the shared writer state still describes the
        // durable header, and `Drop` discards this candidate's dirty pages, so
        // the next writer bump-allocates over the pages it abandoned instead of
        // leaking their ids.
        if invariant_checks {
            let freed = entries.iter().map(|&(_, page_id)| page_id).collect();
            let roots = [
                ("data", new_root),
                ("catalog", new_catalog_root),
                ("commit-history", pending.commit_history_root_page_id),
            ];
            if let Err(violation) = assert_freed_pages_unreachable(
                self.db,
                roots,
                pending.next_page_id,
                &freed,
                new_commit_id,
            )
            .await
            {
                panic!("{violation}");
            }
        }

        // Rewrite the scanned window, hosting it on the floor-safe pages (the
        // cache remainder) and bump-allocating only if those run out, then
        // splice it onto the retained tail. When the window covered the whole
        // chain `retained_tail` is 0 and this is a full rewrite, exactly as
        // before.
        let (new_free_list_root, new_next_page) = freelist::rewrite_chain(
            &self.db.pager,
            self.db.realm_id,
            self.db.page_size,
            entries,
            host_candidates,
            pending.next_page_id,
            retained_tail,
        )
        .await?;
        pending.next_page_id = new_next_page;

        // ── Flush + header swap ──────────────────────────────────────────────
        self.db.pager.flush_main(self.db.realm_id).await?;

        let new_next = pending.next_page_id;
        // Read the A/B cursor after the flush above: sealing those pages may
        // have refreshed the anchor, which moves the slot this commit supersedes.
        let header_cursor = self.db.pager.header_cursor()?;
        let new_seq = header_cursor.next_seq()?;
        let counter_anchor = self.db.pager.pending_anchor();

        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_catalog_root.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());

        let (policy_tag, policy_value) =
            encode_retain_policy(&self.db.options.commit_history_retain);

        let fields = MainDbHeaderFields {
            format_version: crate::pager::structural_header::MAIN_FORMAT_VERSION,
            cipher_id: self.db.cipher_id.as_byte(),
            page_size_log2: page_size_log2(self.db.page_size)?,
            flags: 0,
            file_id: self.db.file_id,
            kek_salt: self.db.kek_salt,
            mk_epoch: self.db.mk_epoch.load(std::sync::atomic::Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: new_root,
            active_root_txn_id: new_commit_id,
            counter_anchor,
            commit_id: CommitId(new_commit_id),
            free_list_root: encode_free_list_root(new_free_list_root),
            catalog_root: catalog_root_bytes,
            apply_journal_root_page_id: 0,
            apply_journal_root_version: 0,
            commit_history_root_page_id: pending.commit_history_root_page_id,
            commit_history_root_version: pending.commit_history_root_version,
            restore_mode: 0,
            next_page_id: new_next,
            commit_retain_policy_tag: policy_tag,
            commit_retain_policy_value: policy_value,
            realm_id: self.db.realm_id,
        };

        let hk_clone = { self.db.hk.read().clone() };
        let new_slot = commit_header(
            &*self.db.vfs,
            &self.db.main_db_path,
            &hk_clone,
            &fields,
            header_cursor.slot,
            self.db.page_size,
        )
        .await?;
        self.db.pager.note_header_written(HeaderCursor {
            slot: new_slot,
            seq: new_seq,
        });
        // From this point the header is durable. Advance writer state before
        // any fallible post-header work so a failed reconciliation can never
        // regress the next durable write. Keep the prior reader snapshot until
        // segment effects have completed and their directories are synced.
        //
        // This is also the single point at which the candidate's advances
        // become shared: everything up to here could still have refused the
        // commit, and a refusal must leave nothing behind.
        pending.publish(&mut self.guard);
        self.guard.root_page_id = new_root;
        self.guard.latest_commit_id = new_commit_id;
        self.guard.catalog_root_page_id = new_catalog_root;
        self.guard.catalog_root_txn_id = new_commit_id;
        self.guard.free_list_root_page_id = new_free_list_root;
        self.committed_or_aborted = true;

        // Black box: record the commit + how many pages it freed into the
        // flight recorder. Freeing commits are the operations most implicated
        // in page recycling, so this trail is what a corruption report needs.
        crate::diag::committed(new_commit_id, all_freed.len());

        // `visibility_guard` was acquired before the reclamation-floor scan in
        // `WriteTxn::begin` and is still held here — it is passed straight into
        // the publication below, so the floor a reader could have observed
        // cannot have moved between the scan and this commit becoming visible.
        if self
            .db
            .finish_durable_commit_visible(
                &self.visibility_guard,
                &self.guard,
                CommitId(new_commit_id),
                counter_anchor,
                &self.pending_segments,
            )
            .await
            .is_err()
        {
            return Err(PagedbError::durably_committed_but_unpublished(CommitId(
                new_commit_id,
            )));
        }

        // The allocator cache is rebuilt from the durable free-list at the next
        // `begin_write`, so nothing is handed off here. The spill tmp file is
        // removed by the caller, on this and every other exit.

        tracing::debug!(
            name = "txn.commit",
            commit_id = new_commit_id,
            "write transaction committed"
        );
        Ok(CommitId(new_commit_id))
    }
}

#[derive(Debug)]
enum FreedPageInvariantViolation {
    Dangling {
        commit_id: u64,
        tree_name: &'static str,
        root: u64,
        description: String,
    },
    Traversal {
        commit_id: u64,
        tree_name: &'static str,
        root: u64,
        error: PagedbError,
    },
    ReachableFreed {
        commit_id: u64,
        page_id: u64,
    },
}

impl std::fmt::Display for FreedPageInvariantViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dangling {
                commit_id,
                tree_name,
                root,
                description,
            } => write!(
                formatter,
                "PAGEDB INVARIANT VIOLATED: commit {commit_id} \
                 {tree_name}_root={root}: {description}"
            ),
            Self::Traversal {
                commit_id,
                tree_name,
                root,
                error,
            } => write!(
                formatter,
                "PAGEDB INVARIANT VIOLATED: commit {commit_id} could not traverse the \
                 new {tree_name} tree rooted at page {root}: {error}"
            ),
            Self::ReachableFreed { commit_id, page_id } => write!(
                formatter,
                "PAGEDB INVARIANT VIOLATED: commit {commit_id} freed page {page_id}, but it is \
                 still reachable from the new data/catalog/history roots"
            ),
        }
    }
}

/// Reject a candidate commit that would free a page still reachable from any
/// of its live trees, or whose live trees cannot be authenticated and decoded.
///
/// Each root is walked twice, and the two walks are not redundant.
/// `find_dangling` selects a node's decoder from the node body's own header
/// byte and reports the first bad *pointer* with its parent, which is what
/// localizes a use-after-free. `collect_all_page_ids` selects the decoder from
/// the *authenticated* envelope kind, so it also catches a page whose envelope
/// and body disagree — invisible to the first walk — and its error must be
/// propagated rather than dropped, or the freed-set check below would pass
/// merely because the reachable set came back short.
async fn assert_freed_pages_unreachable<V: Vfs + Clone>(
    db: &super::super::db::Db<V>,
    roots: [(&'static str, u64); 3],
    next_page_id: u64,
    freed: &HashSet<u64>,
    commit_id: u64,
) -> std::result::Result<(), FreedPageInvariantViolation> {
    let mut reachable = std::collections::BTreeSet::new();
    for (tree_name, root) in roots.into_iter().filter(|(_, root)| *root != 0) {
        let tree = crate::btree::BTree::open(
            db.pager.clone(),
            db.realm_id,
            root,
            next_page_id,
            db.page_size,
        );
        if let Some(description) = tree.find_dangling().await {
            return Err(FreedPageInvariantViolation::Dangling {
                commit_id,
                tree_name,
                root,
                description,
            });
        }
        tree.collect_all_page_ids(&mut reachable)
            .await
            .map_err(|error| FreedPageInvariantViolation::Traversal {
                commit_id,
                tree_name,
                root,
                error,
            })?;
    }

    for page_id in reachable {
        if freed.contains(&page_id) {
            return Err(FreedPageInvariantViolation::ReachableFreed { commit_id, page_id });
        }
    }
    Ok(())
}

fn page_size_log2(page_size: usize) -> Result<u8> {
    match page_size {
        4096 => Ok(12),
        8192 => Ok(13),
        16384 => Ok(14),
        32768 => Ok(15),
        65536 => Ok(16),
        _ => Err(PagedbError::Unsupported),
    }
}

/// Encode a `RetainPolicy` into the two header fields `(tag, value)`.
/// tag 0 = Count, tag 1 = Age (seconds), tag 2 = Unbounded, tag 3 = Disabled.
fn encode_retain_policy(policy: &crate::options::RetainPolicy) -> (u8, u64) {
    match policy {
        crate::options::RetainPolicy::Count(n) => (0, u64::from(*n)),
        crate::options::RetainPolicy::Age(d) => (1, d.as_secs()),
        crate::options::RetainPolicy::Unbounded => (2, 0),
        crate::options::RetainPolicy::Disabled => (3, 0),
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::Arc;

    use super::*;
    use crate::OpenOptions;
    use crate::pager::PageKind;
    use crate::vfs::memory::MemVfs;

    const REALM: crate::RealmId = crate::RealmId::new([3u8; 16]);

    async fn populated_db() -> crate::Db<MemVfs> {
        let db = crate::Db::open_internal_with_options(
            MemVfs::new(),
            [7u8; 32],
            4096,
            REALM,
            OpenOptions::default(),
        )
        .await
        .unwrap();
        let mut write = db.begin_write().await.unwrap();
        write.put(b"live", b"value").await.unwrap();
        write.commit().await.unwrap();
        db
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invariant_rejects_a_reachable_commit_history_page() {
        let db = populated_db().await;
        let (history_root, next_page_id) = {
            let state = db.writer.lock().await;
            (state.commit_history_root_page_id, state.next_page_id)
        };
        assert_ne!(history_root, 0, "the fixture must create commit history");

        let violation = assert_freed_pages_unreachable(
            &db,
            [
                ("data", 0),
                ("catalog", 0),
                ("commit-history", history_root),
            ],
            next_page_id,
            &HashSet::from([history_root]),
            2,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            violation,
            FreedPageInvariantViolation::ReachableFreed { page_id, .. }
                if page_id == history_root
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invariant_rejects_an_unreadable_root() {
        let db = populated_db().await;
        let next_page_id = db.writer.lock().await.next_page_id;
        let unreadable_root = next_page_id + 100;

        let violation = assert_freed_pages_unreachable(
            &db,
            [
                ("data", unreadable_root),
                ("catalog", 0),
                ("commit-history", 0),
            ],
            unreadable_root + 1,
            &HashSet::new(),
            2,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            violation,
            FreedPageInvariantViolation::Dangling {
                tree_name: "data",
                root,
                ..
            } if root == unreadable_root
        ));
    }

    /// The two walks are complementary, not redundant, and the invariant has to
    /// fail closed when only the second one objects.
    ///
    /// `find_dangling` picks a node's decoder from the body's own header byte;
    /// `collect_all_page_ids` picks it from the authenticated envelope kind. A
    /// page whose envelope says internal while its body is a valid leaf
    /// therefore satisfies the first walk and fails the second. Dropping that
    /// error would leave a short reachable set that the freed-page check would
    /// then clear vacuously.
    #[tokio::test(flavor = "current_thread")]
    async fn invariant_rejects_a_root_whose_authenticated_kind_contradicts_its_body() {
        let db = populated_db().await;
        let (data_root, next_page_id) = {
            let state = db.writer.lock().await;
            (state.root_page_id, state.next_page_id)
        };

        // Re-persist the real leaf root's bytes under the internal-node
        // envelope kind. Copying a live page keeps the body structurally valid,
        // so the disagreement is purely the authenticated kind.
        let (guard, kind) = db.pager.read_main_node(data_root, REALM).await.unwrap();
        assert_eq!(kind, PageKind::BTreeLeaf, "the fixture root must be a leaf");
        let body = guard.body_ref().to_vec();
        drop(guard);
        let forged = next_page_id;
        db.pager
            .write_main_page(forged, REALM, PageKind::BTreeInternal, &body)
            .await
            .unwrap();
        db.pager.flush_main(REALM).await.unwrap();
        db.pager.reset_main_pages();

        let tree =
            crate::btree::BTree::open(db.pager.clone(), REALM, forged, forged + 1, db.page_size);
        assert!(
            tree.find_dangling().await.is_none(),
            "the strict pointer walk is expected to miss a kind disagreement; \
             if it now catches it, this test no longer covers the traversal path"
        );

        let violation = assert_freed_pages_unreachable(
            &db,
            [("data", forged), ("catalog", 0), ("commit-history", 0)],
            forged + 1,
            &HashSet::new(),
            2,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                violation,
                FreedPageInvariantViolation::Traversal {
                    tree_name: "data",
                    root,
                    ..
                } if root == forged
            ),
            "expected a traversal violation, got {violation:?}"
        );
    }

    #[test]
    fn invariant_failure_precedes_durable_publication() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "txn::write::commit::tests::invariant_failure_precedes_durable_publication_child",
                "--nocapture",
            ])
            .env("PAGEDB_INVARIANT_CHECKS", "1")
            .output()
            .unwrap();
        let report = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        // libtest exits 0 when a filter matches nothing, so a successful status
        // on its own would keep reporting green if this path ever drifted —
        // renaming the child, the module, or the file would silently delete the
        // regression. Require evidence that the child actually ran.
        assert!(
            report.contains("1 passed"),
            "the child helper did not run; the filter no longer names it:\n{report}"
        );
        assert!(
            output.status.success(),
            "invariant subprocess failed:\n{report}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "subprocess helper; the parent supplies PAGEDB_INVARIANT_CHECKS"]
    async fn invariant_failure_precedes_durable_publication_child() {
        assert!(std::env::var_os("PAGEDB_INVARIANT_CHECKS").is_some());
        let vfs = MemVfs::new();
        let db = Arc::new(
            crate::Db::open_internal_with_options(
                vfs.clone(),
                [7u8; 32],
                4096,
                crate::RealmId::new([3u8; 16]),
                OpenOptions::default(),
            )
            .await
            .unwrap(),
        );
        {
            let mut write = db.begin_write().await.unwrap();
            write.put(b"live", b"value").await.unwrap();
            write.commit().await.unwrap();
        }
        let (commit_before, data_root, history_state_before) = {
            let state = db.writer.lock().await;
            (
                state.latest_commit_id,
                state.root_page_id,
                (
                    state.next_page_id,
                    state.commit_history_root_page_id,
                    state.commit_history_root_version,
                    state.commit_history_count,
                ),
            )
        };

        let task_db = Arc::clone(&db);
        let failure = tokio::spawn(async move {
            let mut write = task_db.begin_write().await.unwrap();
            write.free_set_loaded.push((0, data_root));
            write.commit().await
        })
        .await;
        assert!(
            failure.is_err(),
            "the injected invariant violation must panic"
        );
        drop(failure);

        let state = db.writer.lock().await;
        assert_eq!(state.latest_commit_id, commit_before);
        assert_eq!(
            (
                state.next_page_id,
                state.commit_history_root_page_id,
                state.commit_history_root_version,
                state.commit_history_count,
            ),
            history_state_before
        );
        drop(state);
        drop(db);

        let reopened = crate::Db::open(
            vfs,
            [7u8; 32],
            4096,
            crate::RealmId::new([3u8; 16]),
            OpenOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(reopened.latest_commit().0, commit_before);
        let read = reopened.begin_read().await.unwrap();
        assert_eq!(
            read.get(b"live").await.unwrap().as_deref(),
            Some(b"value".as_slice())
        );
    }
}
