// SPDX-License-Identifier: Apache-2.0

//! Catalog segment lookup at explicit roots.

use super::super::core::Db;
use crate::pager::Pager;
use crate::vfs::Vfs;
use std::collections::BTreeSet;
use std::sync::Arc;

impl<V: Vfs + Clone> Db<V> {
    /// Refuse an export of a catalog that carries a rekey intent.
    ///
    /// A dropped or failed `rekey_db` leaves its intent durable on a usable handle.
    /// A restored directory refuses the `Standalone` mode that settles an intent, and
    /// `rekey_into_writer` refuses the row, so the copy can never settle it.
    pub(super) async fn refuse_export_with_pending_rekey(
        &self,
        catalog_root_page_id: u64,
        next_page_id: u64,
    ) -> crate::Result<()> {
        if catalog_root_page_id == 0 {
            return Ok(());
        }
        let tree = crate::btree::BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root_page_id,
            next_page_id,
            self.page_size,
        );
        let key = crate::catalog::codec::Catalog::rekey_state_key();
        let Some(row) = tree.get(&key).await? else {
            return Ok(());
        };
        let intent = crate::catalog::codec::Catalog::decode_rekey_state(&row)?;
        Err(crate::errors::PagedbError::rekey_pending(
            intent.source_mk_epoch,
            intent.target_mk_epoch,
        ))
    }

    /// Segment rows of the catalog tree rooted at `catalog_root_page_id`.
    ///
    /// Reads the catalog at an explicit root rather than through a `ReadTxn`, so
    /// a caller comparing a base and a target catalog can hold both at once —
    /// and so the base side can be drawn from the same published snapshot its
    /// page sets came from.
    pub(super) async fn catalog_segment_metas(
        &self,
        pager: &Arc<Pager<V>>,
        catalog_root_page_id: u64,
        next_page_id: u64,
    ) -> crate::Result<Vec<crate::catalog::codec::SegmentMeta>> {
        if catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = crate::btree::BTree::open(
            pager.clone(),
            self.realm_id,
            catalog_root_page_id,
            next_page_id,
            self.page_size,
        );
        let rows = tree
            .scan_prefix(&[crate::catalog::codec::CatalogRowKind::Segment as u8])
            .await?;
        let mut entries = Vec::with_capacity(rows.len());
        for (_, value) in rows {
            entries.push(crate::catalog::codec::Catalog::decode_segment_meta(&value)?);
        }
        Ok(entries)
    }

    pub(super) async fn catalog_segment_ids(
        &self,
        pager: &Arc<Pager<V>>,
        catalog_root_page_id: u64,
        next_page_id: u64,
    ) -> crate::Result<BTreeSet<[u8; 16]>> {
        Ok(self
            .catalog_segment_metas(pager, catalog_root_page_id, next_page_id)
            .await?
            .into_iter()
            .map(|meta| meta.segment_id)
            .collect())
    }
}
