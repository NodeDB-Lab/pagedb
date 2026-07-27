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
            .ok_or(PagedbError::MissingPersistedKey {
                mk_epoch: epoch,
                cipher_id: cipher_id.as_byte(),
            })
    }

    pub(crate) fn remove(&self, epoch: u64, cipher_id: CipherId) {
        let _ = self.keys.write().remove(&(epoch, cipher_id.as_byte()));
    }

    /// An independent keyring holding the same leases.
    ///
    /// A second reader over an alternate file image has to decrypt pages sealed
    /// under every epoch the primary handle can read, and a rekey may have left
    /// several live at once. Seeding the copy from only the active epoch would
    /// make mixed-epoch pages unreadable through it for no reason other than
    /// which handle asked. The copy is a snapshot: later installs and retires on
    /// the primary do not propagate, which is correct for a short-lived reader
    /// that must not observe a key set changing under it mid-walk.
    // The only caller is the incremental-apply staging view, which is
    // native-only.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            keys: parking_lot::RwLock::new(self.keys.read().clone()),
        }
    }
}
