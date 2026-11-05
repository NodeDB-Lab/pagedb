pub mod file;
// Raw submission/completion-queue plumbing — an internal detail of this
// backend, never something an embedder drives directly.
pub(crate) mod ring;
#[cfg(test)]
mod tests;
pub mod vfs;

pub use file::IouringFile;
pub use vfs::IouringVfs;
