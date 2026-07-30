//! Per-realm quota caps: persisting them through the catalog tree and the A/B
//! header, and reading them back.

use std::sync::atomic::Ordering;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RealmQuotas};
use crate::errors::PagedbError;
use crate::pager::anchor::HeaderCursor;
use crate::pager::header::commit_header;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use crate::txn::db::core::{Db, HeaderFieldsParams, encode_root_ref};

impl<V: Vfs + Clone> Db<V> {
    /// Write per-realm quota caps into the catalog B+ tree and persist the
    /// updated catalog root to the A/B header.
    pub async fn set_realm_quotas(&self, realm: RealmId, quotas: RealmQuotas) -> Result<()> {
        self.ensure_usable()?;
        let mut state = self.writer.lock().await;
        self.ensure_usable()?;
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
        let new_catalog_txn_id = state
            .latest_commit_id
            .checked_add(1)
            .ok_or_else(|| PagedbError::arithmetic_overflow("catalog transaction id"))?;

        let header_cursor = self.pager.header_cursor()?;
        let new_seq = header_cursor.next_seq()?;
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
            commit_history_root_page_id: state.commit_history_root_page_id,
            commit_history_root_version: state.commit_history_root_version,
            free_list_root_page_id: state.free_list_root_page_id,
            next_page_id: new_next,
        })?;
        let hk_clone = { self.hk.read().clone() };
        let new_slot = commit_header(
            &*self.vfs,
            &self.main_db_path,
            &hk_clone,
            &fields,
            header_cursor.slot,
            self.page_size,
        )
        .await?;
        self.pager.note_header_written(HeaderCursor {
            slot: new_slot,
            seq: new_seq,
        });

        state.catalog_root_page_id = new_catalog_root;
        state.catalog_root_txn_id = new_catalog_txn_id;
        state.next_page_id = new_next;
        let _ = self
            .finish_durable_commit(
                &state,
                crate::CommitId(state.latest_commit_id),
                counter_anchor,
                &[],
            )
            .await?;

        Ok(())
    }

    /// Read per-realm quota caps from the catalog B+ tree. Returns
    /// `RealmQuotas::default()` if no entry has been written for this realm.
    pub async fn realm_quotas(&self, realm: RealmId) -> Result<RealmQuotas> {
        self.ensure_usable()?;
        let snapshot = *self.snapshot.read();
        let key = Catalog::quota_key(realm);
        let cat_tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            snapshot.catalog_root_page_id,
            snapshot.next_page_id,
            self.page_size,
        );
        match cat_tree.get(&key).await? {
            Some(bytes) => Catalog::decode_realm_quotas(&bytes),
            None => Ok(RealmQuotas::default()),
        }
    }
}
