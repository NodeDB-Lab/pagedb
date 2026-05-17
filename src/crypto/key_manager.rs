//! Per-realm DEK cache. Capacity 256 entries by default; eviction is LRU. The
//! cache holds `Cipher` values (keyed cipher states), not raw key bytes — once
//! a cipher state is built, callers reuse it instead of re-running HKDF +
//! cipher-init on every encrypt/decrypt.

use std::collections::HashMap;
use std::collections::VecDeque;

use crate::RealmId;
use crate::Result;
use crate::errors::PagedbError;

use super::cipher::{Cipher, CipherId};
use super::kdf::{derive_dek, derive_ik};
use super::keys::MasterKey;

const DEFAULT_DEK_LRU_CAPACITY: usize = 256;

/// Cache key: a realm under one master-key epoch resolves to one cipher
/// state. During rekey, multiple epochs may coexist; the cache holds entries
/// for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DekKey {
    realm: RealmId,
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

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look up or derive the cipher for `(realm, mk_epoch, cipher_id)`. The
    /// caller supplies the master key relevant to `mk_epoch`.
    pub fn get_or_derive(
        &mut self,
        realm: RealmId,
        mk_epoch: u64,
        cipher_id: CipherId,
        mk: &MasterKey,
    ) -> Result<&mut Cipher> {
        let key = DekKey {
            realm,
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
                let dek = derive_dek(mk, realm)?;
                Cipher::new_aes_gcm(&dek)
            }
            CipherId::ChaCha20Poly1305 => {
                let dek = derive_dek(mk, realm)?;
                Cipher::new_chacha20(&dek)
            }
            CipherId::PlaintextMac => {
                // IK is shared across realms; we still key the cache entry by
                // realm so the lookup shape is uniform.
                let ik = derive_ik(mk)?;
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

    /// Remove all cache entries whose `mk_epoch` matches `epoch`. This is
    /// called during rekey cleanup to evict stale entries for the old epoch,
    /// allowing subsequent reads of remaining old-epoch pages to re-derive the
    /// correct DEK from the still-valid MK.
    pub fn evict_by_epoch(&mut self, epoch: u64) {
        let victims: Vec<DekKey> = self
            .order
            .iter()
            .filter(|k| k.mk_epoch == epoch)
            .copied()
            .collect();
        for v in &victims {
            self.map.remove(v);
            if let Some(pos) = self.order.iter().position(|k| k == v) {
                self.order.remove(pos);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::derive_mk;

    #[test]
    fn cache_hit_returns_same_state() {
        let mk = derive_mk(&[7; 32], &[0; 16], 0).unwrap();
        let mut lru = DekLru::with_capacity(4);
        let _ = lru
            .get_or_derive(RealmId([1; 16]), 0, CipherId::Aes256Gcm, &mk)
            .unwrap();
        assert_eq!(lru.len(), 1);
        let _ = lru
            .get_or_derive(RealmId([1; 16]), 0, CipherId::Aes256Gcm, &mk)
            .unwrap();
        assert_eq!(lru.len(), 1);
    }

    #[test]
    fn lru_evicts_oldest_on_overflow() {
        let mk = derive_mk(&[7; 32], &[0; 16], 0).unwrap();
        let mut lru = DekLru::with_capacity(2);
        for i in 0..3 {
            let realm = RealmId([u8::try_from(i).unwrap(); 16]);
            let _ = lru
                .get_or_derive(realm, 0, CipherId::Aes256Gcm, &mk)
                .unwrap();
        }
        // Realm 0 should have been evicted; realm 1 and realm 2 remain.
        assert_eq!(lru.len(), 2);
    }
}
