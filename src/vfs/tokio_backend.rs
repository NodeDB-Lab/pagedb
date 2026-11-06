//! Cross-platform native VFS on the Tokio blocking pool. Path operations use
//! `tokio::fs`. Advisory locking is the shared two-layer protocol behind
//! [`TokioLockHandle`], so this backend and every other native backend exclude
//! each other over the same directory. The trait contract from `traits.rs` is the
//! durable surface.
//!
//! File I/O runs `std::fs` calls through `offload`, as the other pool-backed
//! backends do. `tokio::fs::File` orders work inside one handle only. Its queued
//! write outlives a closed handle, and nothing outside it can see that write
//! finish. Each closure here owns its buffer and its `WriteOrder` turn instead,
//! so a write stays ordered after its future drops, across every handle of a file.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::fs;

use crate::Result;
use crate::errors::PagedbError;

use super::blocking::offload;
use super::oslock::LockKind;
use super::traits::{Vfs, VfsFile, canonical_native_path, resolve_native_path};
use super::types::{OpenMode, ReadReq, WriteReq};
use super::write_order::WriteOrder;

/// RAII advisory lock handle returned by `TokioVfs::lock_exclusive` /
/// `lock_shared`. The one native handle type, shared with every other
/// filesystem-backed backend.
pub use super::oslock::NativeLockHandle as TokioLockHandle;

// ---------------------------------------------------------------------------
// TokioVfs
// ---------------------------------------------------------------------------

/// VFS rooted at a directory. Paths supplied to all methods are resolved
/// relative to this root; a leading `/` is stripped. Cloning shares the same
/// root. Locks are process-wide, so instances over one directory contend.
#[derive(Clone)]
pub struct TokioVfs {
    inner: Arc<TokioInner>,
}

struct TokioInner {
    root: PathBuf,
}

impl TokioVfs {
    /// Create a new `TokioVfs` rooted at `root`. The directory must already
    /// exist or be created before the first `open` call.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(TokioInner { root: root.into() }),
        }
    }

    fn canonical_logical_path(path: &str) -> Result<String> {
        canonical_native_path(path)
    }

    fn resolve(&self, path: &str) -> Result<PathBuf> {
        resolve_native_path(&self.inner.root, path)
    }

    /// Return the filesystem root directory of this VFS instance.
    #[must_use]
    pub fn root_path(&self) -> &std::path::Path {
        &self.inner.root
    }

    async fn do_lock(&self, path: &str, kind: LockKind) -> Result<TokioLockHandle> {
        let logical_path = Self::canonical_logical_path(path)?;
        let lock_path = self.resolve(&logical_path)?;
        super::oslock::acquire(lock_path, kind).await
    }
}

// ---------------------------------------------------------------------------
// TokioFile
// ---------------------------------------------------------------------------

/// Handle to an open file.
///
/// Reads and writes seek the shared file cursor and then transfer, on a pool
/// thread, under `cursor`. Each handle owns its cursor, so its I/O is serialized.
/// Writes, syncs, and truncates also hold the file's order until they finish.
pub struct TokioFile {
    file: Arc<std::fs::File>,
    /// Serializes one seek and transfer pair. Taken only on a pool thread.
    cursor: Arc<Mutex<()>>,
    order: WriteOrder,
    writable: bool,
}

impl TokioFile {
    fn shared(&self) -> (Arc<std::fs::File>, Arc<Mutex<()>>) {
        (Arc::clone(&self.file), Arc::clone(&self.cursor))
    }
}

/// Seek and read until `buf` is full or the file ends. Returns the bytes read.
fn read_request(file: &std::fs::File, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let mut handle = file;
    handle
        .seek(SeekFrom::Start(offset))
        .map_err(PagedbError::Io)?;
    let mut total = 0;
    while let Some(rest) = buf.get_mut(total..).filter(|rest| !rest.is_empty()) {
        match handle.read(rest) {
            Ok(0) => break,
            Ok(read) => total += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(PagedbError::Io(error)),
        }
    }
    Ok(total)
}

/// Seek and write all of `buf`.
fn write_request(file: &std::fs::File, offset: u64, buf: &[u8]) -> Result<()> {
    let mut handle = file;
    handle
        .seek(SeekFrom::Start(offset))
        .map_err(PagedbError::Io)?;
    handle.write_all(buf).map_err(PagedbError::Io)
}

/// Copy the bytes a pool call read into the caller's buffer.
fn copy_read(dest: &mut [u8], scratch: &[u8]) {
    for (byte, read) in dest.iter_mut().zip(scratch) {
        *byte = *read;
    }
}

fn checked_write_range(offset: u64, len: usize) -> Result<()> {
    let len = u64::try_from(len)
        .map_err(|_| PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
    offset
        .checked_add(len)
        .ok_or_else(|| PagedbError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Vfs impl for TokioVfs
// ---------------------------------------------------------------------------

impl Vfs for TokioVfs {
    type File = TokioFile;
    type LockHandle = TokioLockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        let p = self.resolve(path)?;
        // Ensure parent directories exist for create modes.
        if matches!(mode, OpenMode::CreateNew | OpenMode::CreateOrOpen)
            && let Some(parent) = p.parent()
        {
            fs::create_dir_all(parent).await.map_err(PagedbError::Io)?;
        }
        let (file, writable) = match mode {
            OpenMode::Read => {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .open(&p)
                    .await
                    .map_err(PagedbError::Io)?;
                (f, false)
            }
            OpenMode::ReadWrite => {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&p)
                    .await
                    .map_err(PagedbError::Io)?;
                (f, true)
            }
            OpenMode::CreateNew => {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&p)
                    .await
                    .map_err(PagedbError::Io)?;
                (f, true)
            }
            OpenMode::CreateOrOpen => {
                let f = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&p)
                    .await
                    .map_err(PagedbError::Io)?;
                (f, true)
            }
        };
        let file = file.into_std().await;
        let (file, order) = offload(move || {
            let order = WriteOrder::for_file(&file)?;
            Ok((file, order))
        })
        .await?;
        order.settled().await;
        Ok(TokioFile {
            file: Arc::new(file),
            cursor: Arc::new(Mutex::new(())),
            order,
            writable,
        })
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        match fs::remove_file(&p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PagedbError::Io(e)),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let f = self.resolve(from)?;
        let t = self.resolve(to)?;
        if let Some(parent) = t.parent() {
            fs::create_dir_all(parent).await.map_err(PagedbError::Io)?;
        }
        fs::rename(&f, &t).await.map_err(PagedbError::Io)
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let p = self.resolve(path)?;
        let mut entries = match fs::read_dir(&p).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(PagedbError::Io(e)),
        };
        let mut out = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(PagedbError::Io)? {
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    async fn mkdir_all(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        fs::create_dir_all(&p).await.map_err(PagedbError::Io)
    }

    async fn sync_dir(&self, path: &str) -> Result<()> {
        let p = self.resolve(path)?;
        // `tokio::fs` has no directory-sync form, so this is the one place the
        // backend reaches for `std::fs` — on the blocking pool, because the
        // sync waits on the device.
        //
        // On platforms where opening a directory handle is unsupported or
        // syncing it returns Unsupported/PermissionDenied (e.g., some Windows
        // filesystems), treat as a no-op — the rename durability guarantee is
        // best-effort in those environments.
        offload(move || {
            let dir = match std::fs::File::open(&p) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                // Opening a directory as a file handle is unsupported on some
                // platforms — notably Windows, where it fails with
                // PermissionDenied ("Access is denied") at open, before
                // sync_all is ever reached. Directory fsync is best-effort
                // there, so treat it as a no-op.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    return Ok(());
                }
                Err(e) => return Err(PagedbError::Io(e)),
            };
            match dir.sync_all() {
                Ok(()) => Ok(()),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    Ok(())
                }
                Err(e) => Err(PagedbError::Io(e)),
            }
        })
        .await
    }

    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        self.do_lock(path, LockKind::Exclusive).await
    }

    fn root_path(&self) -> Option<&std::path::Path> {
        Some(&self.inner.root)
    }

    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        self.do_lock(path, LockKind::Shared).await
    }
}

// ---------------------------------------------------------------------------
// VfsFile impl for TokioFile
// ---------------------------------------------------------------------------

impl VfsFile for TokioFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len();
        let (file, cursor) = self.shared();
        let scratch = offload(move || {
            let mut scratch = vec![0u8; len];
            let _cursor = cursor.lock();
            let read = read_request(&file, offset, &mut scratch)?;
            scratch.truncate(read);
            Ok(scratch)
        })
        .await?;
        copy_read(buf, &scratch);
        Ok(scratch.len())
    }

    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        if reqs.is_empty() {
            return Ok(());
        }
        let plan: Vec<(u64, usize)> = reqs.iter().map(|req| (req.offset, req.buf.len())).collect();
        let (file, cursor) = self.shared();
        let completed = offload(move || {
            let _cursor = cursor.lock();
            let mut out = Vec::with_capacity(plan.len());
            for (offset, len) in plan {
                let mut scratch = vec![0u8; len];
                let read = read_request(&file, offset, &mut scratch)?;
                scratch.truncate(read);
                out.push(scratch);
            }
            Ok(out)
        })
        .await?;
        for (req, scratch) in reqs.iter_mut().zip(completed) {
            copy_read(req.buf, &scratch);
            // Zero the tail past EOF, matching vectored contract: callers see
            // a deterministic buffer state (mirrors MemVfs behaviour).
            for byte in req.buf.iter_mut().skip(scratch.len()) {
                *byte = 0;
            }
        }
        Ok(())
    }

    async fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        checked_write_range(offset, buf.len())?;
        let turn = self.order.enter().await;
        let (file, cursor) = self.shared();
        // The pool thread outlives this future, so it writes from its own copy.
        let data = buf.to_vec();
        offload(move || {
            let _turn = turn;
            let _cursor = cursor.lock();
            write_request(&file, offset, &data)?;
            Ok(data.len())
        })
        .await
    }

    async fn write_at_vectored(&mut self, reqs: &[WriteReq<'_>]) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        for req in reqs {
            checked_write_range(req.offset, req.buf.len())?;
        }
        if reqs.is_empty() {
            return Ok(());
        }
        let batch: Vec<(u64, Vec<u8>)> = reqs
            .iter()
            .map(|req| (req.offset, req.buf.to_vec()))
            .collect();
        let turn = self.order.enter().await;
        let (file, cursor) = self.shared();
        offload(move || {
            let _turn = turn;
            let _cursor = cursor.lock();
            for (offset, data) in &batch {
                write_request(&file, *offset, data)?;
            }
            Ok(())
        })
        .await
    }

    async fn sync(&mut self) -> Result<()> {
        let turn = self.order.enter().await;
        let file = Arc::clone(&self.file);
        offload(move || {
            let _turn = turn;
            file.sync_all().map_err(PagedbError::Io)
        })
        .await
    }

    async fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.writable {
            return Err(PagedbError::ReadOnly);
        }
        let turn = self.order.enter().await;
        let file = Arc::clone(&self.file);
        offload(move || {
            let _turn = turn;
            file.set_len(len).map_err(PagedbError::Io)
        })
        .await
    }

    async fn len(&self) -> Result<u64> {
        let file = Arc::clone(&self.file);
        offload(move || Ok(file.metadata().map_err(PagedbError::Io)?.len())).await
    }

    async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    fn supports_direct_io(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
