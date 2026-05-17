//! RAM-backed VFS used for unit tests, the in-memory `Db` flavor, and as the
//! reference semantic for native backends.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;

use super::traits::{Vfs, VfsFile};
use super::types::{OpenMode, ReadReq, WriteReq};

/// Shared inode storage. A path entry in `MemVfs::files` points to one of
/// these; renames move keys in the map, leaving open handles attached to the
/// same `Arc`.
struct MemInode {
    data: Vec<u8>,
}

/// Lock-state machine for a single path. Released by `MemLockHandle::drop`.
struct MemLock {
    state: Mutex<LockState>,
}

#[derive(Debug, Clone, Copy)]
enum LockState {
    Free,
    Exclusive,
    Shared(u32),
}

#[derive(Debug, Clone, Copy)]
enum LockKind {
    Exclusive,
    Shared,
}

/// RAII handle returned by `lock_exclusive` / `lock_shared`. Releases the
/// underlying state on drop. `Send` because all interior synchronization is
/// behind `Arc<Mutex<_>>`.
pub struct MemLockHandle {
    lock_ref: Arc<MemLock>,
    kind: LockKind,
}

impl Drop for MemLockHandle {
    fn drop(&mut self) {
        let mut state = self.lock_ref.state.lock();
        match (self.kind, *state) {
            (LockKind::Exclusive, LockState::Exclusive)
            | (LockKind::Shared, LockState::Shared(1)) => *state = LockState::Free,
            (LockKind::Shared, LockState::Shared(n)) if n > 1 => {
                *state = LockState::Shared(n - 1);
            }
            // Any other combination is a bug in this module; we can't return
            // an error from Drop, so leave the state alone. A test will catch
            // a mismatched release pattern by observing inconsistent
            // subsequent acquisitions.
            _ => {}
        }
    }
}

/// In-memory virtual file system. Cloning the handle shares the underlying
/// storage; an embedder typically constructs one per logical `Db`.
#[derive(Default, Clone)]
pub struct MemVfs {
    inner: Arc<MemVfsInner>,
}

#[derive(Default)]
struct MemVfsInner {
    files: Mutex<BTreeMap<String, Arc<Mutex<MemInode>>>>,
    locks: Mutex<BTreeMap<String, Arc<MemLock>>>,
}

impl MemVfs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup_or_create_lock(&self, path: &str) -> Arc<MemLock> {
        let mut locks = self.inner.locks.lock();
        locks
            .entry(path.to_string())
            .or_insert_with(|| {
                Arc::new(MemLock {
                    state: Mutex::new(LockState::Free),
                })
            })
            .clone()
    }
}

/// Handle to a file in `MemVfs`. Holds an `Arc` to the inode so a rename of
/// the path does not invalidate this handle.
pub struct MemFile {
    inode: Arc<Mutex<MemInode>>,
    writable: bool,
}

impl Vfs for MemVfs {
    type File = MemFile;
    type LockHandle = MemLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let mut files = self.inner.files.lock();
        let exists = files.contains_key(path);
        let (inode, writable) = match (mode, exists) {
            (OpenMode::Read, true) => (files[path].clone(), false),
            (OpenMode::ReadWrite | OpenMode::CreateOrOpen, true) => (files[path].clone(), true),
            (OpenMode::Read | OpenMode::ReadWrite, false) => {
                return Err(PagedbError::Io(std::io::Error::from(
                    std::io::ErrorKind::NotFound,
                )));
            }
            (OpenMode::CreateNew, true) => {
                return Err(PagedbError::Io(std::io::Error::from(
                    std::io::ErrorKind::AlreadyExists,
                )));
            }
            (OpenMode::CreateNew | OpenMode::CreateOrOpen, false) => {
                let inode = Arc::new(Mutex::new(MemInode { data: Vec::new() }));
                files.insert(path.to_string(), inode.clone());
                (inode, true)
            }
        };
        Ok(MemFile { inode, writable })
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let mut files = self.inner.files.lock();
        files.remove(path);
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let mut files = self.inner.files.lock();
        let Some(inode) = files.remove(from) else {
            return Err(PagedbError::Io(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            )));
        };
        files.insert(to.to_string(), inode);
        Ok(())
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let prefix = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{path}/")
        };
        let files = self.inner.files.lock();
        let mut out: Vec<String> = files
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(ToString::to_string))
            // Only direct children, not deep paths.
            .filter(|rest| !rest.contains('/'))
            .collect();
        out.sort();
        Ok(out)
    }

    async fn mkdir_all(&self, _path: &str) -> Result<()> {
        // In-memory backend has no persistent directory entries; mkdir is a no-op.
        Ok(())
    }

    async fn sync_dir(&self, _path: &str) -> Result<()> {
        // In-memory backend has no durability semantics; sync_dir is a no-op.
        Ok(())
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        let lock_ref = self.lookup_or_create_lock(path);
        let mut state = lock_ref.state.lock();
        match *state {
            LockState::Free => {
                *state = LockState::Exclusive;
                drop(state);
                Ok(MemLockHandle {
                    lock_ref,
                    kind: LockKind::Exclusive,
                })
            }
            _ => Err(PagedbError::AlreadyLocked),
        }
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        let lock_ref = self.lookup_or_create_lock(path);
        let mut state = lock_ref.state.lock();
        let next = match *state {
            LockState::Free => LockState::Shared(1),
            LockState::Shared(n) => LockState::Shared(n + 1),
            LockState::Exclusive => return Err(PagedbError::AlreadyLocked),
        };
        *state = next;
        drop(state);
        Ok(MemLockHandle {
            lock_ref,
            kind: LockKind::Shared,
        })
    }
}

impl VfsFile for MemFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let inode = self.inode.lock();
        let offset = usize::try_from(offset)
            .map_err(|_| PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        if offset >= inode.data.len() {
            return Ok(0);
        }
        let available = inode.data.len() - offset;
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&inode.data[offset..offset + n]);
        Ok(n)
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        let inode = self.inode.lock();
        for req in reqs.iter_mut() {
            let offset = usize::try_from(req.offset).map_err(|_| {
                PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput))
            })?;
            let buf_len = req.buf.len();
            let available = inode.data.len().saturating_sub(offset);
            let n = buf_len.min(available);
            if n > 0 {
                req.buf[..n].copy_from_slice(&inode.data[offset..offset + n]);
            }
            // Zero the tail if the read short-reads past EOF, matching the
            // "all-or-nothing" vectored contract: callers see a deterministic
            // buffer state. Native backends mirror this by zeroing past-EOF.
            for b in &mut req.buf[n..] {
                *b = 0;
            }
        }
        Ok(())
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        let mut inode = self.inode.lock();
        let offset = usize::try_from(offset)
            .map_err(|_| PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        let end = offset + buf.len();
        if end > inode.data.len() {
            inode.data.resize(end, 0);
        }
        inode.data[offset..end].copy_from_slice(buf);
        Ok(buf.len())
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        let mut inode = self.inode.lock();
        for req in reqs {
            let offset = usize::try_from(req.offset).map_err(|_| {
                PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput))
            })?;
            let end = offset + req.buf.len();
            if end > inode.data.len() {
                inode.data.resize(end, 0);
            }
            inode.data[offset..end].copy_from_slice(req.buf);
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        Ok(())
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        let mut inode = self.inode.lock();
        let len = usize::try_from(len)
            .map_err(|_| PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        inode.data.resize(len, 0);
        Ok(())
    }

    async fn len(&self) -> Result<u64> {
        let inode = self.inode.lock();
        u64::try_from(inode.data.len())
            .map_err(|_| PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))
    }

    async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    fn supports_direct_io(&self) -> bool {
        false
    }
}
