//! Per-(realm, file) DEK cache. Capacity 256 entries by default; eviction is
//! LRU. The cache holds `Cipher` values (keyed cipher states), not raw key
//! bytes — once a cipher state is built, callers reuse it instead of re-running
//! HKDF + cipher-init on every encrypt/decrypt.

use std::collections::HashMap;
use std::collections::VecDeque;

use crate::RealmId;
use crate::Result;
use crate::errors::PagedbError;

use super::cipher::{Cipher, CipherId};
use super::kdf::{derive_dek, derive_ik};
use super::keys::MasterKey;

const DEFAULT_DEK_LRU_CAPACITY: usize = 256;

/// Cache key: one realm, in one file, under one master-key epoch and cipher
/// resolves to one cipher state. During rekey, multiple epochs may coexist;
/// the cache holds entries for each.
///
/// `file_id` is part of the key because it is part of the derivation — see
/// [`derive_dek`] for why keys are scoped per file. Omitting it here would
/// hand one file the cipher state built for another, which is the nonce-reuse
/// hazard the scoping exists to remove, reintroduced at the cache layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DekKey {
    realm: RealmId,
    file_id: [u8; 16],
    mk_epoch: u64,
    cipher_id_byte: u8,
}

/// Bounded DEK / IK cache. Returns `&mut Cipher` so callers can encrypt /
/// decrypt without owning the cache. Caller passes the MK relevant to
/// `mk_epoch`; the cache invokes HKDF on miss.
pub struct DekLru {
    map: HashMap<DekKey, Cipher>,
    order: VecDeque<DekKey>,
    capacity: usize,
}

impl Default for DekLru {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_DEK_LRU_CAPACITY)
    }
}

impl DekLru {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
        }
    }

    /// Number of cached entries. Only the eviction tests read this — the cache
    /// enforces its own bound internally against `capacity`.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Remove every cached cipher state derived from one retired epoch/cipher.
    pub fn invalidate_epoch(&mut self, mk_epoch: u64, cipher_id: CipherId) {
        let cipher_id_byte = cipher_id.as_byte();
        self.map
            .retain(|key, _| key.mk_epoch != mk_epoch || key.cipher_id_byte != cipher_id_byte);
        self.order
            .retain(|key| key.mk_epoch != mk_epoch || key.cipher_id_byte != cipher_id_byte);
    }

    /// Look up or derive the cipher for `(realm, file_id, mk_epoch,
    /// cipher_id)`. The caller supplies the master key relevant to `mk_epoch`.
    ///
    /// `file_id` must be the identity that seeds the file's nonce generator —
    /// `Pager::file_identity` produces it for every file the pager knows, and
    /// the segment writer/reader pass their `segment_id`.
    pub fn get_or_derive(
        &mut self,
        realm: RealmId,
        file_id: [u8; 16],
        mk_epoch: u64,
        cipher_id: CipherId,
        mk: &MasterKey,
    ) -> Result<&mut Cipher> {
        let key = DekKey {
            realm,
            file_id,
            mk_epoch,
            cipher_id_byte: cipher_id.as_byte(),
        };
        if self.map.contains_key(&key) {
            // Move to MRU.
            if let Some(pos) = self.order.iter().position(|k| *k == key) {
                let k = self.order.remove(pos).expect("position came from iter");
                self.order.push_back(k);
            }
            return self
                .map
                .get_mut(&key)
                .ok_or_else(|| PagedbError::Io(std::io::Error::other("dek lru contract")));
        }

        let cipher = match cipher_id {
            CipherId::Aes256Gcm => {
                let dek = derive_dek(mk, realm, &file_id)?;
                Cipher::new_aes_gcm(&dek)
            }
            CipherId::ChaCha20Poly1305 => {
                let dek = derive_dek(mk, realm, &file_id)?;
                Cipher::new_chacha20(&dek)
            }
            CipherId::PlaintextMac => {
                let ik = derive_ik(mk, realm, &file_id)?;
                Cipher::new_plaintext_mac(ik)
            }
        };

        if self.map.len() >= self.capacity {
            if let Some(victim) = self.order.pop_front() {
                self.map.remove(&victim);
            }
        }
        self.order.push_back(key);
        self.map.insert(key, cipher);
        self.map
            .get_mut(&key)
            .ok_or_else(|| PagedbError::Io(std::io::Error::other("dek lru insert")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::derive_mk;

    const FILE: [u8; 16] = [0x5A; 16];

    #[test]
    fn cache_hit_returns_same_state() {
        let mk = derive_mk(&[7; 32], &[0; 16], 0).unwrap();
        let mut lru = DekLru::with_capacity(4);
        let _ = lru
            .get_or_derive(RealmId([1; 16]), FILE, 0, CipherId::Aes256Gcm, &mk)
            .unwrap();
        assert_eq!(lru.len(), 1);
        let _ = lru
            .get_or_derive(RealmId([1; 16]), FILE, 0, CipherId::Aes256Gcm, &mk)
            .unwrap();
        assert_eq!(lru.len(), 1);
    }

    #[test]
    fn retirement_invalidates_only_matching_epoch_and_cipher() {
        let mk = derive_mk(&[7; 32], &[0; 16], 0).unwrap();
        let mut lru = DekLru::with_capacity(4);
        let _ = lru
            .get_or_derive(RealmId([1; 16]), FILE, 0, CipherId::Aes256Gcm, &mk)
            .unwrap();
        let _ = lru
            .get_or_derive(RealmId([1; 16]), FILE, 0, CipherId::ChaCha20Poly1305, &mk)
            .unwrap();
        let _ = lru
            .get_or_derive(RealmId([1; 16]), FILE, 1, CipherId::Aes256Gcm, &mk)
            .unwrap();

        lru.invalidate_epoch(0, CipherId::Aes256Gcm);

        assert_eq!(lru.len(), 2);
    }

    /// Two files in one realm must not share a cache entry: handing file B the
    /// state derived for file A would put both on one key, which is exactly
    /// the nonce-space collision the per-file derivation removes.
    #[test]
    fn cache_separates_files_within_one_realm() {
        let mk = derive_mk(&[7; 32], &[0; 16], 0).unwrap();
        let mut lru = DekLru::with_capacity(4);
        let realm = RealmId([1; 16]);
        let _ = lru
            .get_or_derive(realm, [0xAA; 16], 0, CipherId::Aes256Gcm, &mk)
            .unwrap();
        let _ = lru
            .get_or_derive(realm, [0xBB; 16], 0, CipherId::Aes256Gcm, &mk)
            .unwrap();
        assert_eq!(lru.len(), 2);
    }

    #[test]
    fn lru_evicts_oldest_on_overflow() {
        let mk = derive_mk(&[7; 32], &[0; 16], 0).unwrap();
        let mut lru = DekLru::with_capacity(2);
        for i in 0..3 {
            let realm = RealmId([u8::try_from(i).unwrap(); 16]);
            let _ = lru
                .get_or_derive(realm, FILE, 0, CipherId::Aes256Gcm, &mk)
                .unwrap();
        }
        // Realm 0 should have been evicted; realm 1 and realm 2 remain.
        assert_eq!(lru.len(), 2);
    }
}
