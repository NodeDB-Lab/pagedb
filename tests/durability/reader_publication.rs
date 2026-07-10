//! Reader creation is local to one `Db` handle and does not publish a commit.

use pagedb::vfs::memory::MemVfs;
use pagedb::{CommitId, Db, RealmId};

const PAGE: usize = 4096;
const KEK: [u8; 32] = [11u8; 32];
const REALM: RealmId = RealmId::new([3u8; 16]);

async fn write_value(db: &Db<MemVfs>, key: &[u8], value: &[u8]) -> CommitId {
    let mut txn = db.begin_write().await.unwrap();
    txn.put(key, value).await.unwrap();
    txn.commit().await.unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn read_constructors_preserve_the_published_commit() {
    let db = Db::open_internal(MemVfs::new(), KEK, PAGE, REALM)
        .await
        .unwrap();
    let first = write_value(&db, b"first", b"one").await;
    let second = write_value(&db, b"second", b"two").await;
    let before = db.latest_commit();
    let before_stats = db.stats().await.unwrap();

    let current = db.begin_read().await.unwrap();
    let internal = db.begin_read_non_abortable().await.unwrap();
    let historical = db.begin_read_at(first).await.unwrap();

    assert_eq!(current.commit_id(), second);
    assert_eq!(internal.commit_id(), second);
    assert_eq!(historical.commit_id(), first);
    assert_eq!(db.latest_commit(), before);
    assert_eq!(
        db.stats().await.unwrap().latest_commit_id,
        before_stats.latest_commit_id
    );
    assert_eq!(db.stats().await.unwrap().tracked_readers, 3);

    drop(current);
    drop(internal);
    drop(historical);
    assert_eq!(db.stats().await.unwrap().tracked_readers, 0);

    let next = write_value(&db, b"third", b"three").await;
    assert_eq!(next.value(), second.value() + 1);
}
