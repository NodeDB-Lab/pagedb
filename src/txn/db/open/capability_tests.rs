//! Mixed-slot compatibility and refusal-before-mutation regressions.

use super::*;
use crate::pager::format::structural_header::{decode_main_db_header, encode_main_db_header};
use crate::vfs::VfsFile;
use crate::vfs::memory::{MemFile, MemVfs};
use crate::vfs::types::{OpenMode, ReadReq, WriteReq};

const KEK: [u8; 32] = [0x3c; 32];
const REALM: RealmId = RealmId::new([0x3c; 16]);
const PAGE: usize = 4096;
const UNKNOWN: u32 = 1 << 7;

async fn store() -> MemVfs {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), KEK, PAGE, REALM)
        .await
        .unwrap();
    for value in [b"old", b"new"] {
        let mut write = db.begin_write().await.unwrap();
        write.put(b"key", value).await.unwrap();
        write.commit().await.unwrap();
    }
    drop(db);
    vfs
}

async fn contents(vfs: &MemVfs) -> Vec<u8> {
    let mut file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    let mut bytes = vec![0; usize::try_from(file.len().await.unwrap()).unwrap()];
    crate::vfs::traits::read_exact_at(&mut file, 0, &mut bytes)
        .await
        .unwrap();
    bytes
}

async fn set_slot(vfs: &MemVfs, slot: usize, seq: u64, unknown: bool, authentic: bool) {
    let mut file = vfs.open("/main.db", OpenMode::Read).await.unwrap();
    let mut bytes = vec![0; PAGE];
    read_header_slot(&mut file, (slot * PAGE) as u64, &mut bytes)
        .await
        .unwrap();
    let salt: [u8; 16] = bytes[32..48].try_into().unwrap();
    let epoch = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
    let hk = derive_hk(&derive_mk(&KEK, &salt, epoch).unwrap()).unwrap();
    let mut fields = decode_main_db_header(&bytes, &hk, PAGE).unwrap();
    fields.seq = seq;
    if unknown {
        fields.flags |= UNKNOWN;
    }
    let mut bytes = encode_main_db_header(&fields, &hk, PAGE).unwrap();
    if !authentic {
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
    }
    let mut file = vfs.open("/main.db", OpenMode::ReadWrite).await.unwrap();
    crate::vfs::traits::write_all_at(&mut file, (slot * PAGE) as u64, &bytes)
        .await
        .unwrap();
    file.sync().await.unwrap();
}

async fn assert_refused(vfs: MemVfs) {
    let before = contents(&vfs).await;
    let paths_before = vfs.list_dir("/").await.unwrap();
    // Any attempt to mutate or enter recovery fails immediately, even if it
    // would leave the same final bytes or be swallowed by error handling.
    match Db::open_existing(NoMutation(vfs.clone()), KEK, PAGE, REALM).await {
        Err(PagedbError::HeaderCapabilityUnsupported { unknown_flags }) => {
            assert_eq!(unknown_flags, UNKNOWN);
        }
        result => panic!(
            "expected capability refusal, got {:?}",
            result.map(|_| "opened")
        ),
    }
    assert_eq!(contents(&vfs).await, before);
    assert_eq!(vfs.list_dir("/").await.unwrap(), paths_before);
}

#[tokio::test]
async fn authenticated_unknown_capability_refuses_every_mixed_slot_order() {
    for slot in 0..2 {
        for seq in [9, 10, 11] {
            let vfs = store().await;
            set_slot(&vfs, slot, seq, true, true).await;
            set_slot(&vfs, 1 - slot, 10, false, true).await;
            assert_refused(vfs).await;
        }
    }
}

#[tokio::test]
async fn authenticated_unknown_capability_survives_a_corrupt_alternate() {
    for slot in 0..2 {
        let vfs = store().await;
        set_slot(&vfs, slot, 10, true, true).await;
        set_slot(&vfs, 1 - slot, 11, false, false).await;
        assert_refused(vfs).await;
    }
}

#[tokio::test]
async fn two_authenticated_unsupported_slots_are_refused_without_mutation() {
    let vfs = store().await;
    set_slot(&vfs, 0, 10, true, true).await;
    set_slot(&vfs, 1, 11, true, true).await;
    assert_refused(vfs).await;
}

#[tokio::test]
async fn public_open_modes_refuse_before_mutating_database_contents() {
    for slot in 0..2 {
        for (other_unknown, other_authentic) in [(false, true), (true, true), (false, false)] {
            let vfs = store().await;
            set_slot(&vfs, slot, 11, true, true).await;
            set_slot(&vfs, 1 - slot, 10, other_unknown, other_authentic).await;
            assert_public_modes_refused(vfs).await;
        }
    }
}

async fn assert_public_modes_refused(vfs: MemVfs) {
    let before = contents(&vfs).await;
    for mode in [DbMode::Standalone, DbMode::ReadOnly, DbMode::Observer] {
        let result = match mode {
            DbMode::Standalone => {
                Db::open(
                    NoMutation(vfs.clone()),
                    KEK,
                    PAGE,
                    REALM,
                    OpenOptions::default(),
                )
                .await
            }
            DbMode::ReadOnly => {
                Db::open_read_only(
                    NoMutation(vfs.clone()),
                    KEK,
                    PAGE,
                    REALM,
                    OpenOptions::default(),
                )
                .await
            }
            DbMode::Observer => {
                Db::open_observer(
                    NoMutation(vfs.clone()),
                    KEK,
                    PAGE,
                    REALM,
                    OpenOptions::default(),
                )
                .await
            }
            _ => unreachable!(),
        };
        assert!(matches!(
            result,
            Err(PagedbError::HeaderCapabilityUnsupported {
                unknown_flags: UNKNOWN
            })
        ));
        assert_eq!(contents(&vfs).await, before);
    }
}

#[tokio::test]
async fn unauthenticated_unknown_capability_does_not_prevent_fallback() {
    for slot in 0..2 {
        let vfs = store().await;
        set_slot(&vfs, slot, 11, true, false).await;
        set_slot(&vfs, 1 - slot, 10, false, true).await;
        let db = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
        let reader = db.begin_read().await.unwrap();
        assert!(reader.get(b"key").await.unwrap().is_some());
    }
}

#[tokio::test]
async fn understood_capabilities_preserve_latest_commit() {
    let vfs = store().await;
    let db = Db::open_existing(vfs, KEK, PAGE, REALM).await.unwrap();
    let reader = db.begin_read().await.unwrap();
    assert_eq!(reader.get(b"key").await.unwrap().unwrap().as_ref(), b"new");
}

#[derive(Clone)]
struct NoMutation(MemVfs);

struct ReadFile(MemFile);

#[allow(clippy::unused_async_trait_impl)]
impl Vfs for NoMutation {
    type File = ReadFile;
    type LockHandle = <MemVfs as Vfs>::LockHandle;

    async fn open(&self, path: &str, mode: OpenMode) -> Result<Self::File> {
        assert!(matches!(mode, OpenMode::Read | OpenMode::ReadWrite));
        assert_eq!(
            path, "/main.db",
            "refusal must precede recovery-file access"
        );
        Ok(ReadFile(self.0.open(path, OpenMode::Read).await?))
    }
    async fn remove(&self, _: &str) -> Result<()> {
        panic!("remove before refusal")
    }
    async fn rename(&self, _: &str, _: &str) -> Result<()> {
        panic!("rename before refusal")
    }
    async fn list_dir(&self, _: &str) -> Result<Vec<String>> {
        panic!("recovery scan before refusal")
    }
    async fn mkdir_all(&self, _: &str) -> Result<()> {
        panic!("mkdir before refusal")
    }
    async fn sync_dir(&self, _: &str) -> Result<()> {
        panic!("sync_dir before refusal")
    }
    async fn lock_exclusive(&self, path: &str) -> Result<Self::LockHandle> {
        // Public opens acquire sentinels before reading headers. Preserve that
        // protocol; on disk, acquiring a lock may materialize a sentinel file.
        self.0.lock_exclusive(path).await
    }
    async fn lock_shared(&self, path: &str) -> Result<Self::LockHandle> {
        self.0.lock_shared(path).await
    }
}

#[allow(clippy::unused_async_trait_impl)]
impl VfsFile for ReadFile {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.0.read_at(offset, buf).await
    }
    async fn read_at_vectored(&self, reqs: &mut [ReadReq<'_>]) -> Result<()> {
        self.0.read_at_vectored(reqs).await
    }
    async fn write_at(&mut self, _: u64, _: &[u8]) -> Result<usize> {
        panic!("write before refusal")
    }
    async fn write_at_vectored(&mut self, _: &[WriteReq<'_>]) -> Result<()> {
        panic!("write before refusal")
    }
    async fn sync(&mut self) -> Result<()> {
        panic!("sync before refusal")
    }
    async fn truncate(&mut self, _: u64) -> Result<()> {
        panic!("truncate before refusal")
    }
    async fn len(&self) -> Result<u64> {
        self.0.len().await
    }
    async fn is_empty(&self) -> Result<bool> {
        self.0.is_empty().await
    }
    fn supports_direct_io(&self) -> bool {
        false
    }
}
