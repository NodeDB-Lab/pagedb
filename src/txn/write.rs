//! `WriteTxn` — exclusive write session backed by a `CoW` B+ tree. On commit,
//! flushes dirty pages, writes the new A/B header, and advances the
//! visibility commit id.

use std::sync::atomic::Ordering;

use tracing;

use tokio::sync::MutexGuard;

use crate::btree::BTree;
use crate::catalog::codec::{Catalog, RealmQuotas, SegmentMeta};
use crate::crypto::aad::{Aad, AadFields};
use crate::crypto::cipher::Cipher;
use crate::crypto::kdf::derive_spill_key;
use crate::crypto::nonce::Nonce;
use crate::errors::{PagedbError, QuotaKind};
use crate::pager::header::commit_header;
use crate::pager::structural_header::MainDbHeaderFields;
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile};
use crate::{CommitId, RealmId, Result};

use super::db::{CommitHistoryMeta, Db, PendingTombstone, WriterState};

/// Opaque handle returned by [`SpillScope::append`]. Pass to
/// [`SpillScope::read`] to decrypt and retrieve the bytes.
#[derive(Debug, Clone, Copy)]
pub struct ScratchOffset(u64);

/// Metadata for one ciphertext chunk in the per-txn spill scratch file.
/// Stored in memory only; the tmp file is discarded at commit/abort.
#[derive(Clone)]
pub(crate) struct SpillSegmentMeta {
    /// Byte offset of this chunk (ciphertext body start) in the tmp file.
    pub offset: u64,
    /// Length of the original plaintext in bytes.
    pub plaintext_len: u32,
    /// Length of ciphertext body (without the 16-byte tag) in bytes.
    /// Total on-disk size for this chunk = `ciphertext_len + 16`.
    pub ciphertext_len: u32,
    /// The 12-byte nonce used to encrypt this chunk, stored verbatim so we
    /// can reconstruct a `Nonce` on read without an additional lookup.
    pub nonce_bytes: [u8; 12],
}

/// A borrowed view into an active `WriteTxn` that offers AEAD-encrypted spill
/// storage in a per-transaction tmp file.
///
/// The tmp file lives at `tmp/scratch-<txn_seq>`. It is created lazily on the
/// first `append` call and removed at `commit` or `abort` (best-effort).
///
/// Nonce scheme: `txn_seq_le6 ‖ segment_index_le6`.
/// - First 6 bytes: the low 6 bytes of `txn_seq` in little-endian order.
/// - Last 6 bytes: the low 6 bytes of the per-append segment index in
///   little-endian order.
///
/// This guarantees uniqueness across all appends within a txn and across
/// independent txns (different `txn_seq`), without requiring a durable
/// nonce anchor (the tmp file is discarded before any subsequent txn can
/// reuse the same `txn_seq`).
pub struct SpillScope<'scope, 'db, V: Vfs + Clone> {
    txn: &'scope mut WriteTxn<'db, V>,
}

impl<V: Vfs + Clone> SpillScope<'_, '_, V> {
    /// Encrypt `bytes` under the per-txn spill key and append the ciphertext
    /// plus 16-byte AEAD tag to the tmp file. Returns a `ScratchOffset` handle
    /// usable with [`read`](Self::read).
    ///
    /// Returns `PagedbError::Quota { kind: QuotaKind::ScratchPages, … }` when
    /// the cumulative ciphertext bytes (body + tag) would exceed the
    /// `OpenOptions::scratch_bytes` budget.
    pub async fn append(&mut self, bytes: &[u8]) -> Result<ScratchOffset> {
        let limit = self.txn.db.options.scratch_bytes as u64;
        let segment_index = self.txn.spill_segments.len() as u64;

        // Extract immutable db fields before taking a mutable borrow for the
        // cipher. Rust cannot prove these are disjoint borrows through the
        // &mut reference, so we copy them out first.
        let mk_epoch = self
            .txn
            .db
            .mk_epoch
            .load(std::sync::atomic::Ordering::SeqCst);
        let realm_id = self.txn.db.realm_id;
        let file_id = self.txn.db.file_id;

        // Build the per-append nonce: txn_seq_le6 || segment_index_le6.
        let nonce = self.txn.next_spill_nonce(segment_index);

        // Derive the spill cipher lazily (mutably borrows txn, then releases).
        self.txn.ensure_spill_cipher()?;
        let cipher_id_byte = self
            .txn
            .spill_cipher
            .as_ref()
            .expect("just derived")
            .id()
            .as_byte();

        // Build AAD: binds cipher_id, a spill sentinel page_kind (0xFE),
        // mk_epoch, this segment's index (as page_id), realm_id, and file_id.
        let aad = Aad::from_fields(AadFields {
            cipher_id: cipher_id_byte,
            page_kind: 0xFE,
            mk_epoch,
            page_id: segment_index,
            realm_id,
            segment_id: file_id,
        });

        let mut body = bytes.to_vec();
        let tag = self
            .txn
            .spill_cipher
            .as_ref()
            .expect("derived above")
            .encrypt(&nonce, &aad, &mut body)?;

        // ciphertext body + 16-byte tag.
        let pers_len = body.len() as u64 + 16;
        let new_total = self.txn.spill_bytes_used.saturating_add(pers_len);
        if new_total > limit {
            return Err(PagedbError::quota(
                self.txn.db.realm_id,
                QuotaKind::ScratchPages,
                new_total,
                limit,
            ));
        }

        // Lazy: create tmp dir and file on first append.
        let path = self.txn.ensure_spill_path().await?;

        let mut file = self.txn.db.vfs.open(&path, OpenMode::CreateOrOpen).await?;
        let body_offset = self.txn.spill_bytes_used;
        let tag_offset = body_offset + body.len() as u64;
        file.write_at(body_offset, &body).await?;
        file.write_at(tag_offset, &tag).await?;
        file.sync().await?;

        let plaintext_len = u32::try_from(bytes.len()).map_err(|_| PagedbError::PayloadTooLarge)?;
        let ciphertext_len = u32::try_from(body.len()).map_err(|_| PagedbError::PayloadTooLarge)?;

        self.txn.spill_segments.push(SpillSegmentMeta {
            offset: body_offset,
            plaintext_len,
            ciphertext_len,
            nonce_bytes: *nonce.as_bytes(),
        });
        self.txn.spill_bytes_used = new_total;
        self.txn
            .db
            .spill_bytes_in_use
            .store(new_total, std::sync::atomic::Ordering::Relaxed);

        Ok(ScratchOffset(segment_index))
    }

    /// Decrypt and return the bytes previously written via
    /// [`append`](Self::append) at `handle`.
    pub async fn read(&self, handle: ScratchOffset) -> Result<Vec<u8>> {
        let idx = usize::try_from(handle.0).map_err(|_| PagedbError::NotFound)?;
        let meta = self
            .txn
            .spill_segments
            .get(idx)
            .ok_or(PagedbError::NotFound)?
            .clone();
        let path = self.txn.spill_path.as_ref().ok_or(PagedbError::NotFound)?;

        let file = self.txn.db.vfs.open(path, OpenMode::Read).await?;

        let body_len = meta.ciphertext_len as usize;
        let mut body = vec![0u8; body_len];
        let mut tag = [0u8; 16];
        file.read_at(meta.offset, &mut body).await?;
        file.read_at(meta.offset + body_len as u64, &mut tag)
            .await?;

        let cipher = self.txn.spill_cipher_readonly()?;
        let nonce = Nonce::from_bytes(meta.nonce_bytes);
        let aad = Aad::from_fields(AadFields {
            cipher_id: cipher.id().as_byte(),
            page_kind: 0xFE,
            mk_epoch: self
                .txn
                .db
                .mk_epoch
                .load(std::sync::atomic::Ordering::SeqCst),
            page_id: handle.0,
            realm_id: self.txn.db.realm_id,
            segment_id: self.txn.db.file_id,
        });

        cipher.decrypt(&nonce, &aad, &mut body, &tag)?;
        body.truncate(meta.plaintext_len as usize);
        Ok(body)
    }
}

/// A handle to a named durable monotonic counter, scoped to a `WriteTxn`.
///
/// The counter starts at `0` if it has never been written. Values are stored
/// as 8-byte little-endian `u64` catalog rows with key prefix `0x02`.
///
/// Monotonicity guarantee: `set(v)` returns `PagedbError::Aborted` when
/// `v < current`; `increment_by` can never produce a value smaller than the
/// current one. Values only survive once the enclosing `WriteTxn::commit`
/// succeeds.
pub struct CounterRef<'a, V: Vfs + Clone> {
    catalog_tree: &'a mut BTree<V>,
    main_tree: &'a mut BTree<V>,
    key: Vec<u8>,
}

impl<V: Vfs + Clone> CounterRef<'_, V> {
    /// Return the current counter value, or `0` if no row exists yet.
    pub async fn get(&self) -> Result<u64> {
        match self.catalog_tree.get(&self.key).await? {
            Some(v) => Catalog::decode_counter(&v),
            None => Ok(0),
        }
    }

    /// Set the counter to `value`. Returns `PagedbError::Aborted` when
    /// `value < current` (strict monotonicity).
    pub async fn set(&mut self, value: u64) -> Result<()> {
        let current = self.get().await?;
        if value < current {
            return Err(PagedbError::Aborted);
        }
        Self::sync_to(self.main_tree, self.catalog_tree);
        let bytes = Catalog::encode_counter(value);
        self.catalog_tree.put(&self.key, &bytes).await?;
        Self::sync_from(self.catalog_tree, self.main_tree);
        Ok(())
    }

    /// Increment the counter by `delta` and return the new value. Returns
    /// `PagedbError::NonceCounterExhausted` on `u64` overflow.
    pub async fn increment_by(&mut self, delta: u64) -> Result<u64> {
        let current = self.get().await?;
        let next = current
            .checked_add(delta)
            .ok_or(PagedbError::NonceCounterExhausted)?;
        Self::sync_to(self.main_tree, self.catalog_tree);
        let bytes = Catalog::encode_counter(next);
        self.catalog_tree.put(&self.key, &bytes).await?;
        Self::sync_from(self.catalog_tree, self.main_tree);
        Ok(next)
    }

    /// Advance the catalog allocator cursor to be at least as high as the
    /// main tree's before a catalog write.
    fn sync_to(main: &BTree<V>, catalog: &mut BTree<V>) {
        let shared = main.next_page_id().max(catalog.next_page_id());
        catalog.set_next_page_id(shared);
    }

    /// After a catalog write, propagate any advances back to the main tree.
    fn sync_from(catalog: &BTree<V>, main: &mut BTree<V>) {
        let c = catalog.next_page_id();
        if main.next_page_id() < c {
            main.set_next_page_id(c);
        }
    }
}

/// Deferred filesystem operation applied after the A/B header is durable.
pub(crate) enum SegmentSideEffect {
    Promote { segment_id: [u8; 16] },
    Tombstone { segment_id: [u8; 16] },
}

/// An exclusive write transaction. At most one `WriteTxn` exists per `Db` at
/// any time — the writer mutex enforces this. Either `commit` or `abort` must
/// be called; if the `WriteTxn` is dropped without either, dirty pages are
/// silently discarded (equivalent to abort).
pub struct WriteTxn<'db, V: Vfs + Clone> {
    db: &'db Db<V>,
    guard: MutexGuard<'db, WriterState>,
    btree: BTree<V>,
    catalog_tree: BTree<V>,
    pending_segments: Vec<SegmentSideEffect>,
    committed_or_aborted: bool,
    /// Monotonic per-txn sequence number; assigned at `begin` from
    /// `Db::txn_seq.fetch_add(1, Relaxed) + 1`. The first `WriteTxn` on a
    /// fresh Db gets `txn_seq == 1`, making `tmp/scratch-1` predictable in
    /// tests.
    pub(crate) txn_seq: u64,
    /// Lazily derived spill cipher. `None` until the first `spill_scope` append.
    pub(crate) spill_cipher: Option<Cipher>,
    /// Lazily created path to the per-txn spill tmp file (`tmp/scratch-<seq>`).
    pub(crate) spill_path: Option<String>,
    /// Cumulative bytes (ciphertext body + tag) written to the spill file.
    pub(crate) spill_bytes_used: u64,
    /// Per-append metadata used by `SpillScope::read` to reconstruct AAD/nonce.
    pub(crate) spill_segments: Vec<SpillSegmentMeta>,
}

impl<'db, V: Vfs + Clone> WriteTxn<'db, V> {
    pub(crate) async fn begin(db: &'db Db<V>) -> Result<WriteTxn<'db, V>> {
        let guard = db.writer.lock().await;
        // If any reader is pinned, freed pages from prior snapshots must not be
        // recycled within this txn. Set the reuse threshold to next_page_id so
        // that only pages allocated in this session (and then freed within it)
        // can be recycled.
        let reuse_threshold = {
            let readers = db.tracked_readers.lock();
            if readers.is_empty() {
                0
            } else {
                guard.next_page_id
            }
        };
        let mut btree = BTree::open(
            db.pager.clone(),
            db.realm_id,
            guard.root_page_id,
            guard.next_page_id,
            db.page_size,
        );
        btree.set_reuse_threshold(reuse_threshold);
        btree.set_free_page_cache(db.free_page_cache.clone());
        let mut catalog_tree = BTree::open(
            db.pager.clone(),
            db.realm_id,
            guard.catalog_root_page_id,
            guard.next_page_id,
            db.page_size,
        );
        catalog_tree.set_reuse_threshold(reuse_threshold);
        catalog_tree.set_free_page_cache(db.free_page_cache.clone());
        // Assign a txn_seq starting from 1: fetch_add returns the old value (0
        // for the first call), so we add 1 to produce 1-based ids.
        let txn_seq = db.txn_seq.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(Self {
            db,
            guard,
            btree,
            catalog_tree,
            pending_segments: Vec::new(),
            committed_or_aborted: false,
            txn_seq,
            spill_cipher: None,
            spill_path: None,
            spill_bytes_used: 0,
            spill_segments: Vec::new(),
        })
    }

    /// Return a [`SpillScope`] that writes AEAD-encrypted bytes to a per-txn
    /// tmp file within the `scratch_bytes` budget from `OpenOptions`.
    pub fn spill_scope(&mut self) -> SpillScope<'_, 'db, V> {
        SpillScope { txn: self }
    }

    /// Lazily derive and cache the per-txn spill cipher (AES-256-GCM keyed
    /// with a spill-specific HKDF derivation from the master key).
    pub(crate) fn ensure_spill_cipher(&mut self) -> Result<&Cipher> {
        if self.spill_cipher.is_none() {
            let pager_mk = self.db.pager.mk();
            let key = derive_spill_key(&pager_mk, &self.db.file_id, self.txn_seq)?;
            self.spill_cipher = Some(Cipher::new_aes_gcm(&key));
        }
        Ok(self.spill_cipher.as_ref().expect("just set"))
    }

    /// Return a reference to the cached spill cipher for read paths (does NOT
    /// lazily create — callers must have already called `ensure_spill_cipher`
    /// or `append` at least once, which guarantees the cipher exists).
    pub(crate) fn spill_cipher_readonly(&self) -> Result<&Cipher> {
        self.spill_cipher.as_ref().ok_or(PagedbError::NotFound)
    }

    /// Lazily create the `tmp/` directory and return the spill file path.
    pub(crate) async fn ensure_spill_path(&mut self) -> Result<String> {
        if self.spill_path.is_none() {
            self.db.vfs.mkdir_all("tmp").await?;
            let path = format!("tmp/scratch-{}", self.txn_seq);
            self.spill_path = Some(path);
        }
        Ok(self.spill_path.clone().expect("just set"))
    }

    /// Build the per-append nonce deterministically from `(txn_seq, segment_index)`.
    ///
    /// Layout: `txn_seq_le6 ‖ segment_index_le6` (6 + 6 = 12 bytes).
    /// Uniqueness: nonces are unique per-txn (distinct `segment_index`) and
    /// across txns (distinct `txn_seq` in first 6 bytes). No durable anchor
    /// is needed because the tmp file is discarded before any key reuse
    /// could matter.
    pub(crate) fn next_spill_nonce(&self, segment_index: u64) -> Nonce {
        let mut bytes = [0u8; 12];
        let seq_le = self.txn_seq.to_le_bytes();
        let idx_le = segment_index.to_le_bytes();
        bytes[..6].copy_from_slice(&seq_le[..6]);
        bytes[6..].copy_from_slice(&idx_le[..6]);
        Nonce::from_bytes(bytes)
    }

    /// Remove the spill tmp file if it was created. Errors are swallowed
    /// (best-effort cleanup); the file is transient anyway.
    pub(crate) async fn cleanup_spill_async(&mut self) {
        if let Some(path) = self.spill_path.take() {
            let _ = self.db.vfs.remove(&path).await;
        }
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.btree.get(key).await
    }

    pub async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.btree.put(key, value).await
    }

    /// Append a key-value pair under the monotonic-key invariant.
    ///
    /// Subsequent calls within the same `WriteTxn` skip the
    /// `path_to_leaf_for_key` descent by reusing the cached rightmost
    /// path; splits and explicitly-invalidating operations (regular `put`,
    /// `delete`) force a re-descent on the next call.
    ///
    /// Intended for op-logs, time-series indexes, FTS posting-list builds
    /// — any workload where the embedder can guarantee monotonically
    /// increasing keys.
    ///
    /// # Errors
    ///
    /// Returns [`PagedbError::AppendNotMonotonic`] if `key` is not
    /// strictly greater than the previously-appended key in this txn.
    pub async fn put_append(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.btree.put_append(key, value).await
    }

    pub async fn delete(&mut self, key: &[u8]) -> Result<bool> {
        self.btree.delete(key).await
    }

    pub async fn put_batch(&mut self, sorted: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        self.btree.put_batch(sorted).await
    }

    pub async fn delete_batch(&mut self, sorted: Vec<Vec<u8>>) -> Result<()> {
        self.btree.delete_batch(sorted).await
    }

    pub async fn delete_range(&mut self, start: &[u8], end: &[u8]) -> Result<u64> {
        self.btree.delete_range(start, end).await
    }

    /// Return a `CounterRef` scoped to this transaction for the named counter.
    ///
    /// The returned handle borrows `self` mutably for its lifetime. Use the
    /// counter, drop the handle, then continue with other transaction
    /// operations. The name must be at most `MAX_SEGMENT_NAME_LEN` bytes
    /// (`PagedbError::NameTooLong` otherwise).
    pub fn counter<'tx>(&'tx mut self, name: &str) -> Result<CounterRef<'tx, V>> {
        let key = Catalog::counter_key(name.as_bytes())?;
        Ok(CounterRef {
            catalog_tree: &mut self.catalog_tree,
            main_tree: &mut self.btree,
            key,
        })
    }

    /// Register a segment under `name` in the catalog and schedule promotion
    /// of its staging file to the live path on commit.
    pub async fn link_segment(&mut self, name: &str, meta: &SegmentMeta) -> Result<()> {
        let key = Catalog::segment_key(self.db.realm_id, name.as_bytes())?;
        if self.catalog_tree.get(&key).await?.is_some() {
            return Err(PagedbError::AlreadyLinked);
        }
        self.enforce_segment_bytes_quota(meta.realm_id, meta.total_bytes, 0)
            .await?;
        let value = Catalog::encode_segment_meta(meta);
        self.sync_allocator_to_catalog();
        self.catalog_tree.put(&key, &value).await?;
        self.sync_allocator_from_catalog();
        self.pending_segments.push(SegmentSideEffect::Promote {
            segment_id: meta.segment_id,
        });
        Ok(())
    }

    /// Remove the catalog row for `name` and schedule a tombstone rename on commit.
    pub async fn unlink_segment(&mut self, name: &str) -> Result<()> {
        let key = Catalog::segment_key(self.db.realm_id, name.as_bytes())?;
        let value = self
            .catalog_tree
            .get(&key)
            .await?
            .ok_or(PagedbError::NotLinked)?;
        let meta = Catalog::decode_segment_meta(&value)?;
        self.sync_allocator_to_catalog();
        let removed = self.catalog_tree.delete(&key).await?;
        self.sync_allocator_from_catalog();
        if !removed {
            return Err(PagedbError::NotLinked);
        }
        self.pending_segments.push(SegmentSideEffect::Tombstone {
            segment_id: meta.segment_id,
        });
        Ok(())
    }

    /// Atomically swap the segment recorded under `name`: tombstone the old
    /// segment id and promote `new_meta`'s staging file on commit.
    pub async fn replace_segment(&mut self, name: &str, new_meta: &SegmentMeta) -> Result<()> {
        let key = Catalog::segment_key(self.db.realm_id, name.as_bytes())?;
        let existing = self
            .catalog_tree
            .get(&key)
            .await?
            .ok_or(PagedbError::NotLinked)?;
        let old_meta = Catalog::decode_segment_meta(&existing)?;
        self.enforce_segment_bytes_quota(
            new_meta.realm_id,
            new_meta.total_bytes,
            old_meta.total_bytes,
        )
        .await?;
        let value = Catalog::encode_segment_meta(new_meta);
        self.sync_allocator_to_catalog();
        self.catalog_tree.put(&key, &value).await?;
        self.sync_allocator_from_catalog();
        self.pending_segments.push(SegmentSideEffect::Tombstone {
            segment_id: old_meta.segment_id,
        });
        self.pending_segments.push(SegmentSideEffect::Promote {
            segment_id: new_meta.segment_id,
        });
        Ok(())
    }

    /// Check if the realm's committed segment bytes plus `new_bytes` minus
    /// `delta_remove_bytes` would exceed the configured cap. Returns `Ok(())`
    /// when no cap is set or the projected total is within the limit.
    async fn enforce_segment_bytes_quota(
        &self,
        realm: RealmId,
        new_bytes: u64,
        delta_remove_bytes: u64,
    ) -> Result<()> {
        let quota_key = Catalog::quota_key(realm);
        let quotas = match self.catalog_tree.get(&quota_key).await? {
            Some(v) => Catalog::decode_realm_quotas(&v)?,
            None => RealmQuotas::default(),
        };
        let Some(limit) = quotas.max_segment_bytes else {
            return Ok(());
        };
        // Scan all catalog segment rows for this realm to sum committed bytes.
        let mut prefix = Vec::with_capacity(17);
        prefix.push(0x01u8); // CatalogRowKind::Segment
        prefix.extend_from_slice(&realm.0);
        let mut end = prefix.clone();
        end.push(0xFF);
        let rows = self.catalog_tree.collect_range(&prefix, &end).await?;
        let mut committed: u64 = 0;
        for (_, v) in rows {
            let meta = Catalog::decode_segment_meta(&v)?;
            committed = committed.saturating_add(meta.total_bytes);
        }
        let after_remove = committed.saturating_sub(delta_remove_bytes);
        let projected = after_remove.saturating_add(new_bytes);
        if projected > limit {
            return Err(PagedbError::quota(
                realm,
                QuotaKind::SegmentBytes,
                projected,
                limit,
            ));
        }
        Ok(())
    }

    /// Flush dirty pages, write the A/B header, apply pending segment side
    /// effects, and publish the new root to readers. Returns the assigned
    /// `CommitId`.
    #[allow(clippy::too_many_lines)]
    pub async fn commit(mut self) -> Result<CommitId> {
        let _span = tracing::debug_span!("txn.commit").entered();
        // Compute commit_id early so we can tag deferred-free entries before
        // the catalog flush.
        let new_commit_id = self.guard.latest_commit_id + 1;

        // Pages freed in this commit that, on the fast-free path, will be
        // pushed to the `Db`'s shared free-page cache *after* the header
        // swap succeeds. Lifted out of the block below so the post-commit
        // handoff can see it.
        let mut fast_freed_for_cache: Vec<u64> = Vec::new();
        // Collect freed pages from both trees and add them to the
        // deferred-free queue in the catalog (tagged with new_commit_id).
        // This keeps the free-list persistent across reopen.
        {
            let freed_from_main = self.btree.drain_freed();
            let freed_from_catalog = self.catalog_tree.drain_freed();
            let all_freed: Vec<u64> = freed_from_main
                .into_iter()
                .chain(freed_from_catalog)
                // Skip reserved pages (0..=3) — they must never enter the free-list.
                .filter(|&pid| pid >= 4)
                .collect();

            // Track the deferred-free pair count for the stall-policy check.
            // Populated below from `free_pages_deferred_batch`'s return value
            // when we wrote pairs this commit; otherwise read once on demand.
            let mut deferred_count: Option<u64> = None;
            // Opt-in fast path: when the embedder has set
            // `skip_freelist_persistence_when_no_readers` AND no readers are
            // pinned at this commit, skip the catalog-tree CoW for the
            // deferred-free row. Instead of orphaning the freed pages we
            // route them into the `Db`'s shared `free_page_cache` further
            // down (after the header swap is durable, so a mid-commit crash
            // can't surface them prematurely). The next writer txn's
            // allocator pops from there, keeping the file size bounded.
            // This is a pagedb extension beyond the architecture spec,
            // documented on
            // `OpenOptions::skip_freelist_persistence_when_no_readers`. The
            // default behavior (option `false`) is spec-conformant: every
            // freed page is persisted to the deferred-free queue.
            let skip_persist = self.db.options.skip_freelist_persistence_when_no_readers
                && self.db.tracked_readers.lock().is_empty();
            // Stash the list for post-commit handoff to the shared cache.
            // Cleared if `skip_persist` is false (pages go to the catalog
            // queue instead) or empty.
            if skip_persist {
                fast_freed_for_cache = all_freed.clone();
            }
            if !all_freed.is_empty() && !skip_persist {
                self.sync_allocator_to_catalog();
                // Batch all freed pages into a single deferred-free put to
                // avoid repeated CoW on the deferred-free row.
                deferred_count = Some(
                    crate::compaction::freelist::free_pages_deferred_batch(
                        &mut self.catalog_tree,
                        new_commit_id,
                        &all_freed,
                    )
                    .await?,
                );
                self.sync_allocator_from_catalog();
            }

            // Evaluate the reader stall policy against the current deferred-free
            // queue depth. On Reject or all-non-abortable AbortOldest this returns
            // an error and the commit is aborted by the `?` propagation.
            {
                let count = if let Some(c) = deferred_count {
                    c
                } else {
                    let dk = crate::catalog::codec::Catalog::deferred_free_key();
                    match self.catalog_tree.get(&dk).await? {
                        Some(bytes) => (bytes.len() as u64) / 16,
                        None => 0,
                    }
                };
                self.db.evaluate_stall_policy(count)?;
            }
        }

        // Materialize each tree's dirty-leaf cache into the pager WITHOUT
        // fsyncing per tree. All three trees (main, catalog, history) share
        // the same file/realm, so their dirty pages live in one pager dirty
        // set — a single `pager.flush_main` below batches them into one
        // fsync. `materialize_dirty` allocates new pages, so re-sync the
        // shared allocator between trees.
        self.btree.materialize_dirty().await?;
        self.sync_allocator_to_catalog();
        self.catalog_tree.materialize_dirty().await?;
        self.sync_allocator_from_catalog();
        let new_root = self.btree.root_page_id();
        let new_catalog_root = self.catalog_tree.root_page_id();
        let new_next_after_trees = self
            .btree
            .next_page_id()
            .max(self.catalog_tree.next_page_id());

        // Stage the guard's next_page_id so the history tree allocates from
        // above the main/catalog pages.
        self.guard.next_page_id = new_next_after_trees;

        // Timestamp for Age-based retention.
        let unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let history_meta = CommitHistoryMeta {
            active_root_page_id: new_root,
            catalog_root_page_id: new_catalog_root,
            free_list_root_page_id: 0,
            next_page_id: new_next_after_trees,
            unix_seconds,
        };
        // Skip the entire commit-history tree maintenance when the policy is
        // Disabled. Saves the per-commit history-tree CoW + flush chain.
        if !matches!(
            self.db.options.commit_history_retain,
            crate::options::RetainPolicy::Disabled
        ) {
            self.db
                .write_commit_history_entry(&mut self.guard, new_commit_id, history_meta)
                .await?;
        }

        // Single pager fsync for all three trees' dirty pages. Replaces the
        // per-tree fsyncs that used to come from `btree.flush`,
        // `catalog_tree.flush`, and `hist_tree.flush` — collapses three
        // fsyncs into one before the header write.
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
            free_list_root: [0; 16],
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
        self.db.pager.commit_anchor(counter_anchor)?;

        // Apply pending segment side effects after the header is durable.
        if !self.pending_segments.is_empty() {
            self.db.vfs.mkdir_all("seg").await?;
            self.db.vfs.sync_dir("seg").await?;
            self.db.vfs.mkdir_all("seg/.tombstone").await?;
            self.db.vfs.sync_dir("seg/.tombstone").await?;
            for effect in &self.pending_segments {
                match effect {
                    SegmentSideEffect::Promote { segment_id } => {
                        let staging = crate::segment::writer::staging_path(segment_id);
                        let live = crate::segment::writer::live_path(segment_id);
                        self.db.vfs.rename(&staging, &live).await?;
                    }
                    SegmentSideEffect::Tombstone { segment_id } => {
                        if self.db.segment_id_is_reader_pinned(*segment_id).await? {
                            self.db.pending_tombstones.lock().push(PendingTombstone {
                                segment_id: *segment_id,
                                commit_id: new_commit_id,
                            });
                        } else {
                            let live = crate::segment::writer::live_path(segment_id);
                            let tomb = format!(
                                "seg/.tombstone/{}.{}",
                                crate::segment::writer::hex_lower(segment_id),
                                new_commit_id,
                            );
                            self.db.vfs.rename(&live, &tomb).await?;
                        }
                    }
                }
            }
            self.db.vfs.sync_dir("seg").await?;
            self.db.vfs.sync_dir("seg/.tombstone").await?;
        }

        self.guard.root_page_id = new_root;
        self.guard.next_page_id = new_next;
        self.guard.active_slot = new_slot;
        self.guard.seq = new_seq;
        self.guard.latest_commit_id = new_commit_id;
        self.guard.catalog_root_page_id = new_catalog_root;
        self.guard.catalog_root_txn_id = new_commit_id;
        // commit_history_root_page_id and commit_history_root_version are
        // already updated inside write_commit_history_entry.
        self.db.latest_commit.store(new_commit_id, Ordering::SeqCst);
        self.committed_or_aborted = true;

        // Post-commit handoff to the shared free-page cache. Only happens
        // on the opt-in fast-free path (`fast_freed_for_cache` is empty
        // otherwise). Deferred to here so a mid-commit failure aborts
        // before the pages become "available for reuse" — the still-active
        // previous root may still reference them.
        if !fast_freed_for_cache.is_empty() {
            let mut cache = self.db.free_page_cache.lock();
            cache.extend(fast_freed_for_cache.iter().copied());
        }

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

    /// Discard all in-flight dirty pages without writing anything durable.
    /// The spill tmp file (if created) is removed before returning (best-effort;
    /// errors are ignored).
    pub async fn abort(mut self) {
        tracing::debug!(name = "txn.abort", "write transaction aborted");
        self.db.pager.discard_dirty_main(self.db.realm_id);
        self.committed_or_aborted = true;
        self.db
            .spill_bytes_in_use
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.cleanup_spill_async().await;
    }

    /// Before a catalog operation: ensure the catalog tree's allocator cursor
    /// is at least as high as the main tree's, so neither tree allocates the
    /// same page id.
    fn sync_allocator_to_catalog(&mut self) {
        let main_next = self.btree.next_page_id();
        let cat_next = self.catalog_tree.next_page_id();
        let shared = main_next.max(cat_next);
        self.catalog_tree.set_next_page_id(shared);
    }

    /// After a catalog operation: propagate any catalog allocation advances
    /// back to the main tree so subsequent main-tree allocations stay above.
    fn sync_allocator_from_catalog(&mut self) {
        let cat_next = self.catalog_tree.next_page_id();
        self.btree.set_next_page_id(cat_next);
    }
}

impl<V: Vfs + Clone> Drop for WriteTxn<'_, V> {
    fn drop(&mut self) {
        if !self.committed_or_aborted {
            self.db.pager.discard_dirty_main(self.db.realm_id);
        }
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
