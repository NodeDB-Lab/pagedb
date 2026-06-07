//! Catalog-backed operations: realm-quota persistence, counter-monotonicity
//! recovery, and commit-history maintenance.

use std::sync::atomic::Ordering;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RealmQuotas};
use crate::pager::header::commit_header;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use super::core::{
    CommitHistoryMeta, Db, HeaderFieldsParams, WriterState, decode_commit_meta, encode_commit_meta,
    encode_root_ref,
};

impl<V: Vfs + Clone> Db<V> {
    /// Scan catalog counter rows and bump any whose stored value is less than
    /// `anchor` up to `anchor`. Called once at open to recover monotonicity
    /// after a torn write. Errors are silently ignored (best-effort); a failure
    /// here does not prevent the database from opening.
    pub(super) async fn recover_counter_monotonicity(&self, anchor: u64) -> Result<()> {
        let (cat_root, next) = {
            let state = self.writer.lock().await;
            (state.catalog_root_page_id, state.next_page_id)
        };
        if cat_root == 0 {
            return Ok(());
        }
        let counter_prefix = vec![crate::catalog::codec::CatalogRowKind::Counter as u8];
        let mut end_prefix = counter_prefix.clone();
        end_prefix.push(0xFF);

        let cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            cat_root,
            next,
            self.page_size,
        );
        let rows = cat_tree.collect_range(&counter_prefix, &end_prefix).await?;
        let mut rows_to_bump: Vec<(Vec<u8>, u64)> = Vec::new();
        for (k, v) in &rows {
            if let Ok(val) = Catalog::decode_counter(v) {
                if val < anchor {
                    rows_to_bump.push((k.clone(), anchor));
                    tracing::debug!(
                        name = "counter.monotonicity_recover",
                        old_value = val,
                        anchor,
                        "bumping counter to anchor"
                    );
                }
            }
        }
        if rows_to_bump.is_empty() {
            return Ok(());
        }

        // Perform a mini write-txn to persist the bumped values.
        let state = self.writer.lock().await;
        let mut cat_tree_w = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        for (k, v) in &rows_to_bump {
            let encoded = Catalog::encode_counter(*v);
            cat_tree_w.put(k, &encoded).await?;
        }
        cat_tree_w.flush().await?;
        let new_cat_root = cat_tree_w.root_page_id();
        let new_next = cat_tree_w.next_page_id().max(state.next_page_id);
        let new_commit_id = state.latest_commit_id + 1;
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();
        let catalog_root_bytes = encode_root_ref(new_cat_root, new_commit_id);
        let fields = self.header_fields(HeaderFieldsParams {
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: new_commit_id,
            catalog_root: catalog_root_bytes,
            commit_history_root_page_id: state.commit_history_root_page_id,
            commit_history_root_version: state.commit_history_root_version,
            next_page_id: new_next,
        })?;
        let hk_clone = self.hk.read().clone();
        let _new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk_clone,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;
        Ok(())
    }

    /// Write per-realm quota caps into the catalog B+ tree and persist the
    /// updated catalog root to the A/B header.
    pub async fn set_realm_quotas(&self, realm: RealmId, quotas: RealmQuotas) -> Result<()> {
        let mut state = self.writer.lock().await;
        let key = Catalog::quota_key(realm);
        let value = Catalog::encode_realm_quotas(&quotas);

        let mut cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        cat_tree.put(&key, &value).await?;
        cat_tree.flush().await?;

        let new_catalog_root = cat_tree.root_page_id();
        let new_next = cat_tree.next_page_id();
        let new_catalog_txn_id = state.latest_commit_id + 1;

        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();
        let catalog_root_bytes = encode_root_ref(new_catalog_root, new_catalog_txn_id);

        let fields = self.header_fields(HeaderFieldsParams {
            mk_epoch: self.mk_epoch.load(Ordering::SeqCst),
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: state.latest_commit_id,
            catalog_root: catalog_root_bytes,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            next_page_id: new_next,
        })?;
        let hk_clone = { self.hk.read().clone() };
        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk_clone,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;

        state.catalog_root_page_id = new_catalog_root;
        state.catalog_root_txn_id = new_catalog_txn_id;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;

        Ok(())
    }

    /// Read per-realm quota caps from the catalog B+ tree. Returns
    /// `RealmQuotas::default()` if no entry has been written for this realm.
    pub async fn realm_quotas(&self, realm: RealmId) -> Result<RealmQuotas> {
        let state = self.writer.lock().await;
        let key = Catalog::quota_key(realm);
        let cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        drop(state);
        match cat_tree.get(&key).await? {
            Some(bytes) => Catalog::decode_realm_quotas(&bytes),
            None => Ok(RealmQuotas::default()),
        }
    }

    /// Insert a commit-history entry into the commit-history B+ tree, prune
    /// according to the retention policy, and return the updated
    /// `(root_page_id, root_version, new_next_page_id)`.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn write_commit_history_entry(
        &self,
        state: &mut WriterState,
        new_commit_id: u64,
        meta: CommitHistoryMeta,
    ) -> Result<()> {
        let min_pinned = {
            let readers = self.tracked_readers.lock();
            readers.iter().map(|r| r.commit_id.0).min()
        };

        let mut hist_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.commit_history_root_page_id,
            state.next_page_id,
            self.page_size,
        );

        // Insert the new entry.
        let key = new_commit_id.to_be_bytes().to_vec();
        let value = encode_commit_meta(&meta);
        let was_new = hist_tree.get(&key).await?.is_none();
        hist_tree.put(&key, &value).await?;

        // Prune according to retention policy.
        let policy = &self.options.commit_history_retain;
        match policy {
            crate::options::RetainPolicy::Unbounded => {
                // No pruning.
                if was_new {
                    state.commit_history_count =
                        Some(state.commit_history_count.unwrap_or(0).saturating_add(1));
                }
            }
            crate::options::RetainPolicy::Count(n) => {
                let count = *n as usize;
                // Fast path: if the cached count is known and the post-insert
                // count is at or below the retain limit, we can skip the
                // full-tree `collect_range` scan entirely.
                let projected = state
                    .commit_history_count
                    .map(|c| if was_new { c.saturating_add(1) } else { c });
                if let Some(p) = projected {
                    if p <= u64::from(*n) {
                        state.commit_history_count = Some(p);
                        // Materialize and return below.
                    } else {
                        // Over-limit: do the scan + prune.
                        let start = 0u64.to_be_bytes().to_vec();
                        let end = u64::MAX.to_be_bytes().to_vec();
                        let all = hist_tree.collect_range(&start, &end).await?;
                        let mut current = all.len() as u64;
                        if all.len() > count {
                            let to_delete = all.len() - count;
                            for (k, _) in all.iter().take(to_delete) {
                                let mut b = [0u8; 8];
                                b.copy_from_slice(&k[..8]);
                                let cid = u64::from_be_bytes(b);
                                if let Some(min) = min_pinned {
                                    if cid >= min {
                                        continue;
                                    }
                                }
                                if hist_tree.delete(k).await? {
                                    current = current.saturating_sub(1);
                                }
                            }
                        }
                        state.commit_history_count = Some(current);
                    }
                } else {
                    // No cached count — do the scan to populate it.
                    let start = 0u64.to_be_bytes().to_vec();
                    let end = u64::MAX.to_be_bytes().to_vec();
                    let all = hist_tree.collect_range(&start, &end).await?;
                    let mut current = all.len() as u64;
                    if all.len() > count {
                        let to_delete = all.len() - count;
                        for (k, _) in all.iter().take(to_delete) {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&k[..8]);
                            let cid = u64::from_be_bytes(b);
                            if let Some(min) = min_pinned {
                                if cid >= min {
                                    continue;
                                }
                            }
                            if hist_tree.delete(k).await? {
                                current = current.saturating_sub(1);
                            }
                        }
                    }
                    state.commit_history_count = Some(current);
                }
            }
            crate::options::RetainPolicy::Age(duration) => {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let threshold = now_secs.saturating_sub(duration.as_secs());
                let start = 0u64.to_be_bytes().to_vec();
                let end = u64::MAX.to_be_bytes().to_vec();
                let all = hist_tree.collect_range(&start, &end).await?;
                let mut current = all.len() as u64;
                for (k, v) in &all {
                    // Never delete the entry we just inserted.
                    if k == &key {
                        continue;
                    }
                    let meta_v = decode_commit_meta(v)?;
                    if meta_v.unix_seconds < threshold {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&k[..8]);
                        let cid = u64::from_be_bytes(b);
                        if let Some(min) = min_pinned {
                            if cid >= min {
                                continue;
                            }
                        }
                        if hist_tree.delete(k).await? {
                            current = current.saturating_sub(1);
                        }
                    }
                }
                state.commit_history_count = Some(current);
            }
            crate::options::RetainPolicy::Disabled => {
                // Unreachable: `WriteTxn::commit` skips this call entirely
                // when the policy is `Disabled`. Treat any accidental call as
                // a no-op rather than panicking, to be defensive.
            }
        }

        // Materialize the history tree's dirty leaves into the pager (so the
        // commit's unified `pager.flush_main` picks them up) without issuing a
        // separate fsync. The caller is responsible for flushing the pager.
        hist_tree.materialize_dirty().await?;
        let new_hist_root = hist_tree.root_page_id();
        let new_next = hist_tree.next_page_id().max(state.next_page_id);

        state.commit_history_root_page_id = new_hist_root;
        state.commit_history_root_version = new_commit_id;
        state.next_page_id = new_next;

        Ok(())
    }
}
