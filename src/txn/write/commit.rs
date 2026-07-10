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
//! Each commit, after materializing all three trees, rebuilds the chain:
//! `(free pages before) − (pages reused this commit) + (pages freed this
//! commit) + (the old chain's own pages)`. Every entry is tagged with the
//! commit that freed it; `begin` recycles only those below the reclamation
//! floor (observable by no reader and no retained-history root). The chain is
//! committed atomically with the header swap, so no freed page is ever lost as
//! an orphan, and a page is recycled only after the commit that overwrote it is
//! durable.
//!
//! Crash-safety of the rewrite: new chain pages are drawn only from pages that
//! were *already free* before this commit (or freshly bump-allocated) — never
//! from pages this commit freed (still live under the old root until the swap)
//! nor from the old chain's own pages (must stay readable until the swap). On a
//! crash before the header swap, the old `free_list_root` and everything it
//! references are intact.

use crate::errors::PagedbError;
use crate::pager::freelist;
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::Vfs;
use crate::{CommitId, Result};
use std::collections::HashSet;

use super::super::db::{CommitHistoryMeta, encode_free_list_root};
use super::txn::WriteTxn;

impl<V: Vfs + Clone> WriteTxn<'_, V> {
    /// Flush dirty pages, write the A/B header, apply pending segment side
    /// effects, and publish the new root to readers. Returns the assigned
    /// `CommitId`.
    #[allow(clippy::too_many_lines)]
    pub async fn commit(mut self) -> Result<CommitId> {
        let _span = tracing::debug_span!("txn.commit");
        // Note: span is not entered via `.entered()` to keep this async fn's
        // future `Send`. Use `tracing::instrument` or enter in sync sections only.
        let new_commit_id = self.guard.latest_commit_id + 1;

        // ── Materialize all trees first ──────────────────────────────────────
        // Done before accounting freed pages so every copy-on-write spine free
        // (which is realized during the flush, not before it) is captured.
        self.btree.materialize_dirty().await?;
        self.sync_allocator_to_catalog();
        self.catalog_tree.materialize_dirty().await?;
        self.sync_allocator_from_catalog();
        let new_root = self.btree.root_page_id();
        let new_catalog_root = self.catalog_tree.root_page_id();
        self.guard.next_page_id = self
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
            next_page_id: self.guard.next_page_id,
            unix_seconds,
        };
        let mut hist_freed: Vec<u64> = Vec::new();
        if !matches!(
            self.db.options.commit_history_retain,
            crate::options::RetainPolicy::Disabled
        ) {
            hist_freed = self
                .db
                .write_commit_history_entry(&mut self.guard, new_commit_id, history_meta)
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
        let consumed: HashSet<u64> = std::mem::take(&mut *self.db.free_page_consumed.lock())
            .into_iter()
            .collect();

        // All free pages after this commit: the loaded chain's entries minus
        // the ones reused, kept with their original freeing-commit tag.
        let prior_free: Vec<(u64, u64)> = std::mem::take(&mut self.free_set_loaded)
            .into_iter()
            .filter(|(_, pid)| !consumed.contains(pid))
            .collect();
        let old_chain: Vec<u64> = std::mem::take(&mut self.old_chain_pages);

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
        // freeing-commit tag) plus this commit's frees and the now-superseded
        // old chain pages, both tagged with this commit.
        let mut entries: Vec<(u64, u64)> = prior_free;
        entries.extend(all_freed.iter().map(|&pid| (new_commit_id, pid)));
        entries.extend(old_chain.iter().map(|&pid| (new_commit_id, pid)));

        // The reader-stall policy fires only on entries genuinely stuck behind
        // a pin — those at/above the reclamation floor. Drainable entries (below
        // it) are being recycled and must not count, or an inherited-but-
        // drainable backlog would spuriously abort a reader on reopen. Evaluated
        // before the chain write so a reject aborts cleanly.
        let stuck = entries
            .iter()
            .filter(|(cid, _)| *cid >= self.reclaim_floor)
            .count() as u64;
        self.db.evaluate_stall_policy(stuck)?;

        // Rewrite the chain, hosting it on the floor-safe pages (the cache
        // remainder) and bump-allocating only if those run out.
        let (new_free_list_root, new_next_page) = freelist::rewrite_chain(
            &self.db.pager,
            self.db.realm_id,
            self.db.page_size,
            entries,
            host_candidates,
            self.guard.next_page_id,
        )
        .await?;
        self.guard.next_page_id = new_next_page;

        // ── Flush + header swap ──────────────────────────────────────────────
        self.db.pager.flush_main(self.db.realm_id).await?;

        let new_next = self.guard.next_page_id;
        let new_seq = self.guard.seq + 1;
        let counter_anchor = self.db.pager.pending_anchor();

        let mut catalog_root_bytes = [0u8; 16];
        catalog_root_bytes[..8].copy_from_slice(&new_catalog_root.to_le_bytes());
        catalog_root_bytes[8..].copy_from_slice(&new_commit_id.to_le_bytes());

        let (policy_tag, policy_value) =
            encode_retain_policy(&self.db.options.commit_history_retain);

        let fields = MainDbHeaderFields {
            format_version: 1,
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
            commit_history_root_page_id: self.guard.commit_history_root_page_id,
            commit_history_root_version: self.guard.commit_history_root_version,
            restore_mode: 0,
            next_page_id: new_next,
            commit_retain_policy_tag: policy_tag,
            commit_retain_policy_value: policy_value,
        };

        let hk_clone = { self.db.hk.read().clone() };
        let new_slot = commit_header(
            &*self.db.vfs,
            &self.db.main_db_path,
            &hk_clone,
            &fields,
            self.guard.active_slot,
            self.db.page_size,
        )
        .await?;
        // From this point the header is durable. Advance writer state before
        // any fallible post-header work so a failed reconciliation can never
        // regress the next durable write. Keep the prior reader snapshot until
        // segment effects have completed and their directories are synced.
        self.guard.root_page_id = new_root;
        self.guard.next_page_id = new_next;
        self.guard.active_slot = new_slot;
        self.guard.seq = new_seq;
        self.guard.latest_commit_id = new_commit_id;
        self.guard.catalog_root_page_id = new_catalog_root;
        self.guard.catalog_root_txn_id = new_commit_id;
        self.guard.free_list_root_page_id = new_free_list_root;
        // commit_history_root_page_id and commit_history_root_version are
        // already updated inside write_commit_history_entry.
        self.committed_or_aborted = true;

        // `visibility_guard` was acquired before the reclamation-floor scan
        // in `WriteTxn::begin` and remains held through this publication.
        let _visibility = &self.visibility_guard;
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
            self.cleanup_spill_async().await;
            self.db
                .spill_bytes_in_use
                .store(0, std::sync::atomic::Ordering::Relaxed);
            return Err(PagedbError::durably_committed_but_unpublished(CommitId(
                new_commit_id,
            )));
        }

        // The allocator cache is rebuilt from the durable free-list at the next
        // `begin_write`, so nothing is handed off here.

        // Remove the spill tmp file (best-effort; error is non-fatal).
        self.cleanup_spill_async().await;

        self.db
            .spill_bytes_in_use
            .store(0, std::sync::atomic::Ordering::Relaxed);
        tracing::debug!(
            name = "txn.commit",
            commit_id = new_commit_id,
            "write transaction committed"
        );
        Ok(CommitId(new_commit_id))
    }
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
