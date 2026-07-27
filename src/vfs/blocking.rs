//! Bridge for file-system work that has no non-blocking form.
//!
//! Some platform primitives — draining an IOCP completion packet, `fsync`,
//! `ftruncate`, every `std::fs` path operation — exist only as calls that park
//! the calling thread until the kernel is finished. Running one directly inside
//! an `async fn` stalls every other task sharing that thread, and on a
//! current-thread runtime that is the entire database. Backends hand such work
//! to [`offload`] instead, which runs it on Tokio's blocking pool.
//!
//! The closure must own everything it touches. That is not merely a `'static`
//! formality: a caller may drop the returned future at any await point, and
//! only a closure that owns its buffers keeps them alive for the kernel to
//! finish writing into.

use crate::Result;
use crate::errors::PagedbError;

/// Run `work` on the blocking pool and await its result.
///
/// A join failure means the pool dropped the task or the closure panicked.
/// Neither can be reported through the closure's own `Result`, so both surface
/// as an I/O error instead of propagating a panic into the caller.
pub(crate) async fn offload<T, F>(work: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) => Err(PagedbError::Io(std::io::Error::other(format!(
            "blocking file-system task did not complete: {error}"
        )))),
    }
}
