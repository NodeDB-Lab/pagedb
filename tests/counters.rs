use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, OpenOptions, PagedbError, RealmId};

const PAGE: usize = 4096;

async fn open() -> Db<MemVfs> {
    Db::open(
        MemVfs::new(),
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn counter_starts_at_zero() {
    let db = open().await;
    let mut w = db.begin_write().await.unwrap();
    {
        let c = w.counter("seq").unwrap();
        assert_eq!(c.get().await.unwrap(), 0);
    }
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn increment_round_trip() {
    let db = open().await;
    {
        let mut w = db.begin_write().await.unwrap();
        {
            let mut c = w.counter("seq").unwrap();
            let v = c.increment_by(1).await.unwrap();
            assert_eq!(v, 1);
            let v = c.increment_by(5).await.unwrap();
            assert_eq!(v, 6);
        }
        w.commit().await.unwrap();
    }
    let mut w = db.begin_write().await.unwrap();
    let c = w.counter("seq").unwrap();
    assert_eq!(c.get().await.unwrap(), 6);
}

#[tokio::test(flavor = "current_thread")]
async fn counters_persist_across_reopen() {
    let vfs = MemVfs::new();
    {
        let db = Db::open(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            OpenOptions::default(),
        )
        .await
        .unwrap();
        let mut w = db.begin_write().await.unwrap();
        {
            let mut c = w.counter("seq").unwrap();
            c.increment_by(1234).await.unwrap();
        }
        w.commit().await.unwrap();
    }
    let db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let mut w = db.begin_write().await.unwrap();
    let c = w.counter("seq").unwrap();
    assert_eq!(c.get().await.unwrap(), 1234);
}

#[tokio::test(flavor = "current_thread")]
async fn multiple_counters_independent() {
    let db = open().await;
    let mut w = db.begin_write().await.unwrap();
    {
        let mut a = w.counter("a").unwrap();
        a.increment_by(10).await.unwrap();
    }
    {
        let mut b = w.counter("b").unwrap();
        b.increment_by(20).await.unwrap();
    }
    {
        let a = w.counter("a").unwrap();
        assert_eq!(a.get().await.unwrap(), 10);
    }
    {
        let b = w.counter("b").unwrap();
        assert_eq!(b.get().await.unwrap(), 20);
    }
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn monotonic_set_smaller_fails() {
    let db = open().await;
    let mut w = db.begin_write().await.unwrap();
    let mut c = w.counter("seq").unwrap();
    c.set(100).await.unwrap();
    let err = c.set(50).await.err().unwrap();
    assert!(matches!(err, PagedbError::Aborted));
}

#[tokio::test(flavor = "current_thread")]
async fn abort_discards_increments() {
    let db = open().await;
    {
        let mut w = db.begin_write().await.unwrap();
        {
            let mut c = w.counter("seq").unwrap();
            c.increment_by(7).await.unwrap();
        }
        w.abort().await;
    }
    let mut w = db.begin_write().await.unwrap();
    let c = w.counter("seq").unwrap();
    assert_eq!(c.get().await.unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn increment_overflow_rejected() {
    let db = open().await;
    let mut w = db.begin_write().await.unwrap();
    let mut c = w.counter("seq").unwrap();
    c.set(u64::MAX).await.unwrap();
    let err = c.increment_by(1).await.err().unwrap();
    assert!(matches!(err, PagedbError::NonceCounterExhausted));
}

#[tokio::test(flavor = "current_thread")]
async fn many_increments_persist_with_intermediate_flush() {
    let vfs = MemVfs::new();
    // One entry point for both the first iteration (which bootstraps) and the
    // rest (which reopen): `Db::open` decides from what is on disk.
    for _ in 0..10u64 {
        let db = Db::open(
            vfs.clone(),
            [9u8; 32],
            PAGE,
            RealmId::new([1; 16]),
            OpenOptions::default(),
        )
        .await
        .unwrap();
        let mut w = db.begin_write().await.unwrap();
        {
            let mut c = w.counter("seq").unwrap();
            for _ in 0..100u64 {
                c.increment_by(1).await.unwrap();
            }
        }
        w.commit().await.unwrap();
        drop(db);
    }
    let db = Db::open(
        vfs,
        [9u8; 32],
        PAGE,
        RealmId::new([1; 16]),
        OpenOptions::default(),
    )
    .await
    .unwrap();
    let mut w = db.begin_write().await.unwrap();
    let c = w.counter("seq").unwrap();
    assert_eq!(c.get().await.unwrap(), 1000);
}
