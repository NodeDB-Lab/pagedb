use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, RealmId};

async fn open_with_page_size(page_size: usize) -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), [7u8; 32], page_size, RealmId::new([1; 16]))
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn open_4096() {
    let db = open_with_page_size(4096).await;
    let mut w = db.begin_write().await.unwrap();
    w.put(b"k", b"v").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(r.get(b"k").await.unwrap().as_deref(), Some(b"v".as_ref()));
}

#[tokio::test(flavor = "current_thread")]
async fn open_8192() {
    let db = open_with_page_size(8192).await;
    let mut w = db.begin_write().await.unwrap();
    w.put(b"key8k", b"val8k").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"key8k").await.unwrap().as_deref(),
        Some(b"val8k".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn open_16384() {
    let db = open_with_page_size(16384).await;
    let mut w = db.begin_write().await.unwrap();
    w.put(b"key16k", b"val16k").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"key16k").await.unwrap().as_deref(),
        Some(b"val16k".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn open_32768() {
    let db = open_with_page_size(32768).await;
    let mut w = db.begin_write().await.unwrap();
    w.put(b"key32k", b"val32k").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"key32k").await.unwrap().as_deref(),
        Some(b"val32k".as_ref())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn open_65536() {
    let db = open_with_page_size(65536).await;
    let mut w = db.begin_write().await.unwrap();
    w.put(b"key64k", b"val64k").await.unwrap();
    w.commit().await.unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"key64k").await.unwrap().as_deref(),
        Some(b"val64k".as_ref())
    );
}
