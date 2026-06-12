//! In-process advisory file locking for the OPFS VFS.
//!
//! OPFS itself exposes no cross-handle locking primitive, so `OpfsVfs`
//! arbitrates `lock_exclusive` / `lock_shared` within the single browser JS
//! realm using the [`LockMap`] reference-counted table. [`OpfsLockHandle`] is
//! the RAII guard handed back to callers; dropping it releases the lock.

#![cfg(all(target_arch = "wasm32", feature = "opfs"))]
// The unsafe Send + Sync impls below are required to satisfy `Vfs: Send + Sync`
// on wasm32. Safety justification is on the impl blocks.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
enum LockKind {
    Exclusive,
    Shared,
}

/// Reference-counted advisory lock table keyed by resolved path.
#[derive(Default)]
pub(super) struct LockMap {
    entries: HashMap<String, (LockKind, u32)>,
}

impl LockMap {
    pub(super) fn try_exclusive(&mut self, path: &str) -> bool {
        if self.entries.contains_key(path) {
            return false;
        }
        self.entries
            .insert(path.to_string(), (LockKind::Exclusive, 1));
        true
    }

    pub(super) fn try_shared(&mut self, path: &str) -> bool {
        match self.entries.get_mut(path) {
            None => {
                self.entries.insert(path.to_string(), (LockKind::Shared, 1));
                true
            }
            Some((LockKind::Shared, n)) => {
                *n += 1;
                true
            }
            Some((LockKind::Exclusive, _)) => false,
        }
    }

    pub(super) fn release(&mut self, path: &str) {
        let remove = match self.entries.get_mut(path) {
            Some((_, n)) if *n <= 1 => true,
            Some((_, n)) => {
                *n -= 1;
                false
            }
            None => false,
        };
        if remove {
            self.entries.remove(path);
        }
    }
}

/// RAII advisory lock handle returned by `lock_exclusive` / `lock_shared`.
pub struct OpfsLockHandle {
    pub(super) path: String,
    pub(super) locks: Arc<Mutex<LockMap>>,
}

// SAFETY: wasm32 is single-threaded by browser spec. All access to
// OpfsLockHandle happens on the spawning thread. The Arc<Mutex<LockMap>>
// field contains no JS types and is naturally Send+Sync.
unsafe impl Send for OpfsLockHandle {}
unsafe impl Sync for OpfsLockHandle {}

impl Drop for OpfsLockHandle {
    fn drop(&mut self) {
        if let Ok(mut map) = self.locks.lock() {
            map.release(&self.path);
        }
    }
}
