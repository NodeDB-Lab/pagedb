use pagedb::vfs::memory::MemVfs;
use pagedb::{CommitId, Db, PagedbError, RealmId, RealmQuotas};

const PAGE: usize = 4096;

async fn open() -> (Db<MemVfs>, MemVfs) {
    let vfs = MemVfs::new();
    let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap();
    (db, vfs)
}

#[tokio::test(flavor = "current_thread")]
async fn quotas_default_on_unset_realm() {
    let (db, _) = open().await;
    let q = db.realm_quotas(RealmId::new([42; 16])).await.unwrap();
    assert_eq!(q, RealmQuotas::default());
}

#[tokio::test(flavor = "current_thread")]
async fn set_and_get_quotas_round_trip() {
    let (db, _) = open().await;
    let q = RealmQuotas {
        max_pages: Some(1000),
        max_dirty_pages: Some(64),
        max_scratch_pages: None,
        max_segment_bytes: Some(10 * 1024 * 1024),
    };
    db.set_realm_quotas(RealmId::new([1; 16]), q).await.unwrap();
    let got = db.realm_quotas(RealmId::new([1; 16])).await.unwrap();
    assert_eq!(got, q);
}

#[tokio::test(flavor = "current_thread")]
async fn quotas_are_per_realm_independent() {
    let (db, _) = open().await;
    let q_a = RealmQuotas {
        max_segment_bytes: Some(1_000_000),
        ..RealmQuotas::default()
    };
    let q_b = RealmQuotas {
        max_segment_bytes: Some(10_000_000),
        ..RealmQuotas::default()
    };
    db.set_realm_quotas(RealmId::new([1; 16]), q_a)
        .await
        .unwrap();
    db.set_realm_quotas(RealmId::new([2; 16]), q_b)
        .await
        .unwrap();
    assert_eq!(db.realm_quotas(RealmId::new([1; 16])).await.unwrap(), q_a);
    assert_eq!(db.realm_quotas(RealmId::new([2; 16])).await.unwrap(), q_b);
    assert_eq!(
        db.realm_quotas(RealmId::new([3; 16])).await.unwrap(),
        RealmQuotas::default()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn set_quotas_persists_across_reopen() {
    let vfs = MemVfs::new();
    let q = RealmQuotas {
        max_pages: Some(7777),
        ..RealmQuotas::default()
    };
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
            .await
            .unwrap();
        db.set_realm_quotas(RealmId::new([1; 16]), q).await.unwrap();
    }
    let db = Db::open_existing(vfs, [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap();
    let got = db.realm_quotas(RealmId::new([1; 16])).await.unwrap();
    assert_eq!(got, q);
}

#[tokio::test(flavor = "current_thread")]
async fn open_existing_recovers_writes() {
    let vfs = MemVfs::new();
    {
        let db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
            .await
            .unwrap();
        let mut w = db.begin_write().await.unwrap();
        w.put(b"foo", b"bar").await.unwrap();
        w.commit().await.unwrap();
    }
    let db = Db::open_existing(vfs, [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap();
    let r = db.begin_read().await.unwrap();
    assert_eq!(
        r.get(b"foo").await.unwrap().as_deref(),
        Some(b"bar".as_ref())
    );
    assert_eq!(db.latest_commit(), CommitId::new(1));
}

#[tokio::test(flavor = "current_thread")]
async fn open_existing_with_wrong_kek_fails() {
    let vfs = MemVfs::new();
    {
        let _db = Db::open_internal(vfs.clone(), [9u8; 32], PAGE, RealmId::new([1; 16]))
            .await
            .unwrap();
    }
    let err = Db::open_existing(vfs, [0u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, PagedbError::Corruption(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn quota_writes_interleave_with_user_writes() {
    let (db, _) = open().await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k1", b"v1").await.unwrap();
        w.commit().await.unwrap();
    }
    db.set_realm_quotas(
        RealmId::new([1; 16]),
        RealmQuotas {
            max_pages: Some(500),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    {
        let mut w = db.begin_write().await.unwrap();
        w.put(b"k2", b"v2").await.unwrap();
        w.commit().await.unwrap();
    }
    let r = db.begin_read().await.unwrap();
    assert_eq!(r.get(b"k1").await.unwrap().as_deref(), Some(b"v1".as_ref()));
    assert_eq!(r.get(b"k2").await.unwrap().as_deref(), Some(b"v2".as_ref()));
    let q = db.realm_quotas(RealmId::new([1; 16])).await.unwrap();
    assert_eq!(q.max_pages, Some(500));
}

#[tokio::test(flavor = "current_thread")]
async fn default_quotas_remove_caps() {
    let (db, _) = open().await;
    db.set_realm_quotas(
        RealmId::new([1; 16]),
        RealmQuotas {
            max_pages: Some(500),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    db.set_realm_quotas(RealmId::new([1; 16]), RealmQuotas::default())
        .await
        .unwrap();
    let q = db.realm_quotas(RealmId::new([1; 16])).await.unwrap();
    assert_eq!(q, RealmQuotas::default());
}
