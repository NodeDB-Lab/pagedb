//! Segment creation, lookup, listing, reader-pin checks, and catalog-level
//! segment replacement.

use std::sync::atomic::Ordering;

use crate::btree::BTree;
use crate::catalog::codec::CatalogRowKind;
use crate::catalog::codec::{Catalog, SegmentKind, SegmentMeta};
use crate::errors::PagedbError;
use crate::segment::reader::SegmentReader;
use crate::segment::writer::SegmentWriter;
use crate::vfs::Vfs;
use crate::{RealmId, Result};

use super::core::{Db, HeaderFieldsParams, WriterState, encode_root_ref};

impl<V: Vfs + Clone> Db<V> {
    /// Create a fresh segment in the given realm. The returned writer holds a
    /// handle to `seg/.staging/<hex(segment_id)>`. Sealing the writer makes
    /// the file durable; publication requires a catalog link.
    pub async fn create_segment(
        &self,
        realm: RealmId,
        kind: SegmentKind,
    ) -> Result<SegmentWriter<V>> {
        self.vfs.mkdir_all("seg/.staging").await?;
        let segment_id = self.next_segment_id();
        SegmentWriter::create_internal(self.pager.clone(), realm, segment_id, self.file_id, kind)
            .await
    }

    /// Open a segment by `(realm, name)` resolved against the live catalog.
    pub async fn open_segment(&self, realm: RealmId, name: &str) -> Result<SegmentReader<V>> {
        let meta = self.lookup_segment(realm, name).await?;
        let limit = u64::try_from(self.options.mmap_view_scratch_bytes).unwrap_or(u64::MAX);
        SegmentReader::open_internal(
            self.pager.clone(),
            meta,
            self.mmap_bytes_in_use.clone(),
            limit,
        )
        .await
    }

    /// List segments in `realm` whose names start with `prefix`. Live catalog.
    pub async fn list_segments(&self, realm: RealmId, prefix: &str) -> Result<Vec<SegmentMeta>> {
        let (catalog_root, next) = {
            let writer = self.writer.lock().await;
            (writer.catalog_root_page_id, writer.next_page_id)
        };
        if catalog_root == 0 {
            return Ok(Vec::new());
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root,
            next,
            self.page_size,
        );
        let start = Catalog::segment_key(realm, prefix.as_bytes())?;
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            out.push(meta);
        }
        Ok(out)
    }

    /// Return `true` if any currently tracked reader's catalog snapshot
    /// contains `segment_id`.
    pub(crate) async fn segment_id_is_reader_pinned(&self, segment_id: [u8; 16]) -> Result<bool> {
        let snapshots = {
            let readers = self.tracked_readers.lock();
            readers
                .iter()
                .map(|r| (r.catalog_root_page_id, r.next_page_id))
                .collect::<Vec<_>>()
        };
        for (root, next) in snapshots {
            if root == 0 {
                continue;
            }
            let tree = BTree::open(
                self.pager.clone(),
                self.realm_id,
                root,
                next,
                self.page_size,
            );
            let start = vec![0x01u8];
            let end = vec![0x02u8];
            let rows = tree.collect_range(&start, &end).await?;
            for (_, v) in rows {
                let meta = Catalog::decode_segment_meta(&v)?;
                if meta.segment_id == segment_id {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    async fn lookup_segment(&self, realm: RealmId, name: &str) -> Result<SegmentMeta> {
        let (catalog_root, next) = {
            let writer = self.writer.lock().await;
            (writer.catalog_root_page_id, writer.next_page_id)
        };
        if catalog_root == 0 {
            return Err(PagedbError::NotFound);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            catalog_root,
            next,
            self.page_size,
        );
        let key = Catalog::segment_key(realm, name.as_bytes())?;
        let value = tree.get(&key).await?.ok_or(PagedbError::NotFound)?;
        Catalog::decode_segment_meta(&value)
    }

    pub(crate) fn next_segment_id(&self) -> [u8; 16] {
        let counter = self.segment_id_counter.fetch_add(1, Ordering::Relaxed);
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        let mut seed = u64::from_le_bytes([
            self.file_id[0],
            self.file_id[1],
            self.file_id[2],
            self.file_id[3],
            self.file_id[4],
            self.file_id[5],
            self.file_id[6],
            self.file_id[7],
        ]) ^ counter
            ^ wall;
        let mut out = [0u8; 16];
        for chunk in out.chunks_mut(8) {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes());
        }
        out
    }

    /// List all segment entries in the catalog.
    pub(super) async fn list_all_segments(&self, state: &WriterState) -> Result<Vec<SegmentMeta>> {
        if state.catalog_root_page_id == 0 {
            return Ok(Vec::new());
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let start = vec![CatalogRowKind::Segment as u8];
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            out.push(meta);
        }
        Ok(out)
    }

    /// Find the catalog name for a segment by its `segment_id`.
    pub(super) async fn find_segment_name(
        &self,
        state: &WriterState,
        segment_id: &[u8; 16],
    ) -> Result<String> {
        if state.catalog_root_page_id == 0 {
            return Err(PagedbError::NotFound);
        }
        let tree = BTree::open(
            self.pager.clone(),
            self.realm_id,
            state.catalog_root_page_id,
            state.next_page_id,
            self.page_size,
        );
        let start = vec![CatalogRowKind::Segment as u8];
        let mut end = start.clone();
        end.push(0xFF);
        let rows = tree.collect_range(&start, &end).await?;
        for (k, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            if meta.segment_id == *segment_id {
                // Key layout: [0x01] || realm_id[16] || name_bytes
                if k.len() > 17 {
                    let name = String::from_utf8_lossy(&k[17..]).into_owned();
                    return Ok(name);
                }
            }
        }
        Err(PagedbError::NotFound)
    }

    /// Replace a segment in the catalog with a new one and commit the header.
    pub(super) async fn replace_segment_in_catalog(
        &self,
        state: &mut WriterState,
        name: &str,
        old_segment_id: &[u8; 16],
        new_meta: &SegmentMeta,
        hk: &crate::crypto::keys::DerivedKey,
        new_mk_epoch: u64,
    ) -> Result<()> {
        let key = Catalog::segment_key(self.realm_id, name.as_bytes())?;
        let value = Catalog::encode_segment_meta(new_meta);

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
        let new_next = cat_tree.next_page_id().max(state.next_page_id);
        let new_commit_id = state.latest_commit_id + 1;
        let new_seq = state.seq + 1;
        let counter_anchor = self.pager.pending_anchor();

        let catalog_root_bytes = encode_root_ref(new_catalog_root, new_commit_id);

        let fields = self.header_fields(HeaderFieldsParams {
            mk_epoch: new_mk_epoch,
            seq: new_seq,
            active_root_page_id: state.root_page_id,
            active_root_txn_id: state.latest_commit_id,
            counter_anchor,
            commit_id: new_commit_id,
            catalog_root: catalog_root_bytes,
            commit_history_root_page_id: 0,
            commit_history_root_version: 0,
            free_list_root_page_id: state.free_list_root_page_id,
            next_page_id: new_next,
        })?;

        let new_slot = crate::pager::header::commit_header(
            &*self.vfs,
            &self.main_db_path,
            hk,
            &fields,
            state.active_slot,
            self.page_size,
        )
        .await?;
        self.pager.commit_anchor(counter_anchor)?;

        // Promote the new segment staging file to live.
        self.vfs.mkdir_all("seg").await?;
        let staging = crate::segment::writer::staging_path(&new_meta.segment_id);
        let live = crate::segment::writer::live_path(&new_meta.segment_id);
        self.vfs.rename(&staging, &live).await?;
        self.vfs.sync_dir("seg").await.ok();

        // Tombstone the old segment.
        let old_live = crate::segment::writer::live_path(old_segment_id);
        let tomb = format!(
            "seg/.tombstone/{}.{}",
            crate::hex::to_hex_lower(old_segment_id),
            new_commit_id,
        );
        self.vfs.mkdir_all("seg/.tombstone").await?;
        self.vfs.rename(&old_live, &tomb).await.ok();
        self.vfs.sync_dir("seg/.tombstone").await.ok();

        state.catalog_root_page_id = new_catalog_root;
        state.next_page_id = new_next;
        state.active_slot = new_slot;
        state.seq = new_seq;
        state.latest_commit_id = new_commit_id;
        self.latest_commit.store(new_commit_id, Ordering::SeqCst);
        self.publish_snapshot(state);

        Ok(())
    }
}
