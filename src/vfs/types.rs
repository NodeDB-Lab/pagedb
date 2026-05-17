//! Supporting types for the `Vfs` and `VfsFile` traits.

/// Open-mode selector for [`super::Vfs::open`]. Maps to OS-level open flags
/// in real backends; for the in-memory backend it dictates creation semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Read-only. Fails with an `io::ErrorKind::NotFound`-mapped error if the
    /// path does not exist.
    Read,
    /// Read and write. Fails if the path does not exist; does not truncate.
    ReadWrite,
    /// Create the path. Fails with `io::ErrorKind::AlreadyExists`-mapped error
    /// if the path already exists. The new file is empty and writable.
    CreateNew,
    /// Create the path if absent, open if present. The opened file is writable;
    /// existing contents are preserved (no truncate).
    CreateOrOpen,
}

/// A single read request in a vectored-read batch. Buffers are filled in place.
pub struct ReadReq<'a> {
    pub offset: u64,
    pub buf: &'a mut [u8],
}

/// A single write request in a vectored-write batch.
pub struct WriteReq<'a> {
    pub offset: u64,
    pub buf: &'a [u8],
}
