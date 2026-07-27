//! Per-`WriteTxn` AEAD-encrypted spill scratch storage.

use crate::Result;
use crate::crypto::aad::{Aad, AadFields};
use crate::crypto::cipher::Cipher;
use crate::crypto::kdf::derive_spill_key;
use crate::crypto::nonce::Nonce;
use crate::errors::{PagedbError, QuotaKind};
use crate::vfs::types::OpenMode;
use crate::vfs::{Vfs, VfsFile, read_exact_at, write_all_at};

use super::txn::WriteTxn;

/// Opaque handle returned by [`SpillScope::append`]. Pass to
/// [`SpillScope::read`] to decrypt and retrieve the bytes.
#[derive(Debug, Clone, Copy)]
pub struct ScratchOffset(u64);

/// Metadata for one ciphertext chunk in the per-txn spill scratch file.
/// Length of the AEAD tag appended to every spill frame.
pub(crate) const SPILL_TAG_LEN: usize = 16;

/// Stored in memory only; the tmp file is discarded at commit/abort.
#[derive(Clone)]
pub(crate) struct SpillSegmentMeta {
    /// Byte offset of this chunk (ciphertext body start) in the tmp file.
    pub offset: u64,
    /// Length of the original plaintext in bytes.
    pub plaintext_len: u32,
    /// Length of ciphertext body (without the AEAD tag) in bytes. Total
    /// on-disk size for this chunk = `ciphertext_len + SPILL_TAG_LEN`.
    pub ciphertext_len: u32,
    /// The 12-byte nonce used to encrypt this chunk, stored verbatim so we
    /// can reconstruct a `Nonce` on read without an additional lookup.
    pub nonce_bytes: [u8; 12],
}

/// A borrowed view into an active `WriteTxn` that offers AEAD-encrypted spill
/// storage in a per-transaction tmp file.
///
/// The tmp file lives at `tmp/scratch-<txn_seq>`. It is created lazily on the
/// first `append` call and removed at `commit` or `abort`. A transaction
/// dropped without either records its path for the next `begin_write` to
/// remove, and whatever a crash leaves behind is swept at the next open.
///
/// Nonce scheme: `txn_seq_le6 ‖ segment_index_le6`.
/// - First 6 bytes: the low 6 bytes of `txn_seq` in little-endian order.
/// - Last 6 bytes: the low 6 bytes of the per-append segment index in
///   little-endian order.
///
/// Uniqueness under one key comes from `txn_seq` being strictly increasing
/// within an open handle and `segment_index` within a transaction. It does not
/// come from the file being deleted: `txn_seq` restarts at 1 on every open, so
/// deletion alone would leave two opens writing one nonce. The spill key is
/// instead derived per open, from a random epoch this handle generates and
/// never persists, so a repeated sequence lands under a different key and no
/// durable nonce anchor is needed.
pub struct SpillScope<'scope, 'db, V: Vfs + Clone> {
    pub(super) txn: &'scope mut WriteTxn<'db, V>,
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

        // ciphertext body + AEAD tag.
        let pers_len = body.len() as u64 + SPILL_TAG_LEN as u64;
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
        let ciphertext_len = body.len();
        // Body and tag are one contiguous frame: a handle must never be
        // returned for a file holding only half of it.
        body.extend_from_slice(&tag);
        write_all_at(&mut file, body_offset, &body).await?;
        file.sync().await?;

        let plaintext_len = u32::try_from(bytes.len()).map_err(|_| PagedbError::PayloadTooLarge)?;
        let ciphertext_len =
            u32::try_from(ciphertext_len).map_err(|_| PagedbError::PayloadTooLarge)?;

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

        let mut file = self.txn.db.vfs.open(path, OpenMode::Read).await?;

        let body_len = meta.ciphertext_len as usize;
        // `usize` is 32-bit on wasm32, where a maximal `ciphertext_len` plus
        // the tag genuinely overflows it.
        let frame_len = body_len
            .checked_add(SPILL_TAG_LEN)
            .ok_or_else(|| PagedbError::arithmetic_overflow("spill frame length"))?;
        let mut frame = vec![0u8; frame_len];
        read_exact_at(&mut file, meta.offset, &mut frame).await?;
        // The split is exact by construction, so the tail is the whole tag.
        let (body, tag_bytes) = frame.split_at_mut(body_len);
        let mut tag = [0u8; SPILL_TAG_LEN];
        tag.copy_from_slice(tag_bytes);

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

        cipher.decrypt(&nonce, &aad, body, &tag)?;
        frame.truncate(meta.plaintext_len as usize);
        Ok(frame)
    }
}

impl<'db, V: Vfs + Clone> WriteTxn<'db, V> {
    /// Return a [`SpillScope`] that writes AEAD-encrypted bytes to a per-txn
    /// tmp file within the `scratch_bytes` budget from `OpenOptions`.
    pub fn spill_scope(&mut self) -> SpillScope<'_, 'db, V> {
        SpillScope { txn: self }
    }

    /// Lazily derive and cache the per-txn spill cipher (AES-256-GCM keyed
    /// with a spill-specific HKDF derivation from the master key).
    pub(crate) fn ensure_spill_cipher(&mut self) -> Result<&Cipher> {
        if self.spill_cipher.is_none() {
            let pager_mk = self.db.pager.mk()?;
            let key = derive_spill_key(
                &pager_mk,
                &self.db.file_id,
                &self.db.spill_epoch,
                self.txn_seq,
            )?;
            self.spill_cipher = Some(Cipher::new_aes_gcm(&key));
        }
        self.spill_cipher.as_ref().ok_or(PagedbError::NotFound)
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
    /// Uniqueness within one key: distinct `segment_index` within a
    /// transaction, distinct `txn_seq` across the transactions of one open
    /// handle. `txn_seq` repeats across opens, which is why the key is scoped
    /// to an open rather than to the store; see the type-level docs.
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
}
