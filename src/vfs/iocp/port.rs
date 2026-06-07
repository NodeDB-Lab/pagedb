//! Shared I/O completion port. One port is held per `IocpVfs`. Every file
//! handle opened by the VFS is associated with this port at open time via
//! `CreateIoCompletionPort`. Operations serialize through a
//! `parking_lot::Mutex` guarding the port: a caller posts a single overlapped
//! `ReadFile` / `WriteFile`, calls `GetQueuedCompletionStatus`, and releases
//! the lock. This mirrors the io_uring backend's "hold the ring, submit,
//! wait" model — intentionally simple, no background reaper thread.
#![allow(unsafe_code)]

use std::sync::Arc;

use parking_lot::Mutex;

use crate::Result;
use crate::errors::PagedbError;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
};

// In windows-sys 0.61 `HANDLE` is `*mut c_void`. NULL handles are null
// pointers; the wrapper uses the constant below for readability.
const NULL_HANDLE: HANDLE = std::ptr::null_mut();

/// Owning wrapper around an IOCP `HANDLE`. Closed on drop.
pub(crate) struct PortHandle {
    handle: HANDLE,
}

impl PortHandle {
    fn create() -> Result<Self> {
        // SAFETY: `INVALID_HANDLE_VALUE` for `FileHandle` + null existing port
        // creates a fresh completion port owning no file. `0` for
        // `NumberOfConcurrentThreads` lets the kernel pick the default
        // (= number of processors), which is what we want.
        let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL_HANDLE, 0, 0) };
        if handle == NULL_HANDLE {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self { handle })
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for PortHandle {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is a valid IOCP handle we created in
        // `PortHandle::create`. Closing is idempotent at the OS level; we
        // ignore the return because Drop cannot propagate errors.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

// SAFETY: An IOCP handle is process-global and may be referenced from any
// thread; the kernel synchronises operations against it internally.
unsafe impl Send for PortHandle {}
// SAFETY: Same justification — the IOCP handle is intrinsically thread-safe.
unsafe impl Sync for PortHandle {}

/// Shared port wrapper. The mutex serialises every overlapped op posted
/// against this port; the file handle and unique completion key let
/// `GetQueuedCompletionStatus` disambiguate the packet we are waiting for in
/// the rare case the kernel returns a stale completion.
pub struct Port {
    pub(crate) inner: Arc<PortInner>,
}

pub(crate) struct PortInner {
    pub(crate) handle: PortHandle,
    /// Lock acquired around every submit + dequeue cycle.
    pub(crate) lock: Mutex<()>,
}

impl Port {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: Arc::new(PortInner {
                handle: PortHandle::create()?,
                lock: Mutex::new(()),
            }),
        })
    }

    /// Associate `file_handle` with this completion port using `key` as the
    /// per-file `CompletionKey`. Returns an error if association fails.
    pub(crate) fn associate(&self, file_handle: HANDLE, key: usize) -> Result<()> {
        // SAFETY: `file_handle` is a valid handle owned by the caller; the
        // port handle is valid as long as `self` exists. Passing an existing
        // port handle as `ExistingCompletionPort` adds the file to that port.
        let rc = unsafe { CreateIoCompletionPort(file_handle, self.inner.handle.raw(), key, 0) };
        // CreateIoCompletionPort returns the port handle on success when
        // associating an existing file; NULL indicates failure.
        if rc == NULL_HANDLE {
            return Err(PagedbError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Block until any completion packet arrives on this port. Returns
    /// (bytes_transferred, completion_key, overlapped_ptr).
    ///
    /// # Safety
    ///
    /// The caller must hold `self.inner.lock` for the entire duration of the
    /// submit + dequeue cycle so that the returned `OVERLAPPED *` is
    /// guaranteed to point to one of *their* in-flight requests (because no
    /// other thread can have submitted on this serialised port). The
    /// `OVERLAPPED` buffer the pointer references must remain valid until
    /// this call returns.
    pub(crate) unsafe fn dequeue(&self) -> std::io::Result<(u32, usize, *mut OVERLAPPED)> {
        let mut bytes: u32 = 0;
        let mut key: usize = 0;
        let mut overlapped: *mut OVERLAPPED = std::ptr::null_mut();
        // SAFETY: All pointers are to local stack variables; `INFINITE` timeout
        // is acceptable because the caller has just posted a request that
        // will produce a completion.
        let rc = unsafe {
            GetQueuedCompletionStatus(
                self.inner.handle.raw(),
                &mut bytes,
                &mut key,
                &mut overlapped,
                u32::MAX,
            )
        };
        if rc == 0 {
            // The MSDN contract: if rc == 0 and overlapped is non-null, the
            // function dequeued a failed I/O packet — we still must report
            // the error from the OS (often a real I/O failure such as
            // ERROR_HANDLE_EOF). If overlapped is null, the call itself
            // failed before dequeueing anything.
            let err = std::io::Error::last_os_error();
            if overlapped.is_null() {
                return Err(err);
            }
            // Failed I/O packet — propagate but still return the dequeue
            // tuple so the caller can match the key/overlapped pointer.
            return Err(err);
        }
        Ok((bytes, key, overlapped))
    }

    pub(crate) fn lock(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.inner.lock.lock()
    }
}
