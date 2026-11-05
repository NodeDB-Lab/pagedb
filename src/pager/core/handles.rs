//! File handle cache and its generation counter.

use std::sync::Arc;
use std::sync::atomic::Ordering as AtomOrd;

use tokio::sync::Mutex as AsyncMutex;

use super::pager::Pager;
use crate::Result;
use crate::pager::cache::FileKey;
use crate::vfs::Vfs;
use crate::vfs::types::OpenMode;

impl<V: Vfs> Pager<V> {
    /// Enable persistent writes after a frozen read-only handle transitions
    /// to Follower mode. Cached read-only file handles are discarded so later
    /// pager operations reopen them with read/write access.
    pub(crate) async fn enable_write_access(&self) {
        self.read_only.store(false, AtomOrd::SeqCst);
        let mut files = self.files.lock().await;
        self.handle_generation.fetch_add(1, AtomOrd::SeqCst);
        files.clear();
    }

    /// Close the cached main.db file handle. The next access reopens the file.
    /// An atomic rename over main.db requires this close. Closing first lets the
    /// rename replace the file on platforms that reject replacing an open file
    /// (Windows). Reopening afterwards picks up the new inode (Unix).
    ///
    /// Each close bumps the handle generation. A swap closes twice. The close
    /// before the rename releases the file. The close after it drops any handle
    /// a read reopened in between. The generation then stops a read that fetched
    /// from the old inode from caching its handle or its page.
    pub async fn close_main_handle(&self) {
        let mut files = self.files.lock().await;
        self.handle_generation.fetch_add(1, AtomOrd::SeqCst);
        files.remove(&FileKey::Main);
    }

    /// The cached handle for `file`, opening and caching one on a miss.
    ///
    /// An open that overlaps a handle invalidation can bind the replaced file.
    /// That handle is discarded and the open runs again.
    pub(super) async fn open_file_handle(&self, file: FileKey) -> Result<Arc<AsyncMutex<V::File>>> {
        let path = match file {
            FileKey::Main => self.cfg.main_db_path.clone(),
            FileKey::ApplyJournal(id) => {
                format!("applyjournal/{}", crate::hex::to_hex_lower(&id))
            }
        };
        loop {
            let generation = {
                let files = self.files.lock().await;
                if let Some(handle) = files.get(&file) {
                    return Ok(handle.clone());
                }
                self.handle_generation.load(AtomOrd::SeqCst)
            };
            let mode = if self.read_only.load(AtomOrd::SeqCst) {
                OpenMode::Read
            } else {
                OpenMode::CreateOrOpen
            };
            let opened = Arc::new(AsyncMutex::new(self.vfs.open(&path, mode).await?));
            let mut files = self.files.lock().await;
            if self.handle_generation.load(AtomOrd::SeqCst) != generation {
                continue;
            }
            if let Some(handle) = files.get(&file) {
                return Ok(handle.clone());
            }
            files.insert(file, opened.clone());
            return Ok(opened);
        }
    }
}
