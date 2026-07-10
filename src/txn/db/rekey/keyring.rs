//! In-memory epoch-key routing for mixed rekey state.

use std::collections::BTreeMap;

use crate::Result;
use crate::crypto::{CipherId, MasterKey};
use crate::errors::PagedbError;

/// Zeroizing master keys indexed by their on-wire `(mk_epoch, cipher_id)`.
/// Entries are memory-only and returned as owned leases so readers can retain
/// their decrypting material while a rekey changes the active writer epoch.
pub(crate) struct EpochKeyring {
    keys: parking_lot::RwLock<BTreeMap<(u64, u8), MasterKey>>,
}

impl EpochKeyring {
    pub(crate) fn new(epoch: u64, cipher_id: CipherId, mk: MasterKey) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert((epoch, cipher_id.as_byte()), mk);
        Self {
            keys: parking_lot::RwLock::new(keys),
        }
    }

    pub(crate) fn install(&self, epoch: u64, cipher_id: CipherId, mk: MasterKey) {
        self.keys.write().insert((epoch, cipher_id.as_byte()), mk);
    }

    pub(crate) fn lease(&self, epoch: u64, cipher_id: CipherId) -> Result<MasterKey> {
        self.keys
            .read()
            .get(&(epoch, cipher_id.as_byte()))
            .cloned()
            .ok_or(PagedbError::ChecksumFailure)
    }

    pub(crate) fn remove(&self, epoch: u64, cipher_id: CipherId) {
        let _ = self.keys.write().remove(&(epoch, cipher_id.as_byte()));
    }
}
