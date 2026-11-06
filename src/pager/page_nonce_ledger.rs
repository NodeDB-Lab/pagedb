//! Test support: the nonce and body of every sealed page a test has seen.
//!
//! The ledger reads raw file bytes. Bytes 12..24 of a page envelope hold its
//! nonce, and the body follows them. Nothing here goes through a seal helper.

use std::collections::{BTreeMap, BTreeSet};

use crate::pager::page_space::is_reserved;
use crate::vfs::{OpenMode, Vfs, VfsFile, read_exact_at};

const NONCE_START: usize = 12;
const NONCE_END: usize = 24;

/// Every body seen under each nonce, across any number of files and moments.
#[derive(Default)]
pub(crate) struct PageNonceLedger {
    bodies: BTreeMap<[u8; 12], BTreeSet<Vec<u8>>>,
}

impl PageNonceLedger {
    /// Record each page of a whole-file image. Header slots hold no page nonce,
    /// and a page that was never sealed holds a zero nonce. Both stay out.
    pub(crate) fn record_image(&mut self, image: &[u8], page_size: usize) {
        for (index, page) in image.chunks_exact(page_size).enumerate() {
            if is_reserved(u64::try_from(index).unwrap()) {
                continue;
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&page[NONCE_START..NONCE_END]);
            if nonce != [0u8; 12] {
                self.bodies
                    .entry(nonce)
                    .or_default()
                    .insert(page[NONCE_END..].to_vec());
            }
        }
    }

    /// Record each page of the file at `path`, as it stands now.
    pub(crate) async fn record_file<V: Vfs>(&mut self, vfs: &V, path: &str, page_size: usize) {
        let image = read_image(vfs, path).await;
        self.record_image(&image, page_size);
    }

    /// Fail unless each nonce has mapped to one body. The same bytes seen twice
    /// are one seal seen twice, so they pass.
    pub(crate) fn assert_page_nonces_are_distinct(&self, context: &str) {
        assert!(
            !self.bodies.is_empty(),
            "{context}: the ledger holds no page"
        );
        let repeated: Vec<&[u8; 12]> = self
            .bodies
            .iter()
            .filter(|(_, bodies)| bodies.len() > 1)
            .map(|(nonce, _)| nonce)
            .collect();
        assert!(
            repeated.is_empty(),
            "{context}: these nonces map to more than one body: {repeated:02x?}"
        );
    }
}

/// The whole file at `path`, read directly from the VFS.
pub(crate) async fn read_image<V: Vfs>(vfs: &V, path: &str) -> Vec<u8> {
    let mut file = vfs.open(path, OpenMode::Read).await.unwrap();
    let len = usize::try_from(file.len().await.unwrap()).unwrap();
    let mut image = vec![0u8; len];
    read_exact_at(&mut file, 0, &mut image).await.unwrap();
    image
}
