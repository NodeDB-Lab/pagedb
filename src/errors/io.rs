use super::PagedbError;

/// Classify a backend I/O failure on its way into the error spine.
///
/// Hand-written rather than derived with `#[from]` so device exhaustion is
/// separated from ordinary I/O exactly once, at the single boundary every `?`
/// on a VFS call already crosses. Classifying at raise sites instead would mean
/// every writer, flush, seal, and header commit repeating the same match — and
/// one that forgot would silently re-bury a full disk inside [`PagedbError::Io`].
impl From<std::io::Error> for PagedbError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::StorageFull {
            return Self::NoSpace;
        }
        Self::Io(error)
    }
}
