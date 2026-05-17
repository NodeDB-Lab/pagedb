use pagedb::errors::QuotaKind;
use pagedb::vfs::memory::MemVfs;
use pagedb::{Db, PagedbError, RealmId, RealmQuotas, SegmentKind, SegmentPageKind};

const PAGE: usize = 4096;

async fn open() -> Db<MemVfs> {
    Db::open_internal(MemVfs::new(), [9u8; 32], PAGE, RealmId::new([1; 16]))
        .await
        .unwrap()
}

async fn create_segment_of_size(
    db: &Db<MemVfs>,
    realm: RealmId,
    page_count: usize,
) -> pagedb::SegmentMeta {
    let mut w = db
        .create_segment(realm, SegmentKind::Unspecified)
        .await
        .unwrap();
    for _ in 0..page_count {
        w.append_page(SegmentPageKind::Data, b"x").await.unwrap();
    }
    w.seal().await.unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn link_segment_no_quota_succeeds() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    let meta = create_segment_of_size(&db, realm, 1).await;
    let mut w = db.begin_write().await.unwrap();
    w.link_segment("seg", &meta).await.unwrap();
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn link_segment_under_quota_succeeds() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    db.set_realm_quotas(
        realm,
        RealmQuotas {
            max_segment_bytes: Some(1_000_000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    let meta = create_segment_of_size(&db, realm, 1).await;
    let mut w = db.begin_write().await.unwrap();
    w.link_segment("seg", &meta).await.unwrap();
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn link_segment_over_quota_rejected() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    // Set a tight cap so the second link exceeds it.
    db.set_realm_quotas(
        realm,
        RealmQuotas {
            max_segment_bytes: Some(20_000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    let meta1 = create_segment_of_size(&db, realm, 1).await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.link_segment("a", &meta1).await.unwrap();
        w.commit().await.unwrap();
    }
    let meta2 = create_segment_of_size(&db, realm, 1).await;
    let mut w = db.begin_write().await.unwrap();
    let err = w.link_segment("b", &meta2).await.err().unwrap();
    assert!(matches!(
        err,
        PagedbError::Quota {
            kind: QuotaKind::SegmentBytes,
            ..
        }
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn quota_isolated_per_realm() {
    let db = open().await;
    let realm_a = RealmId::new([1; 16]);
    let realm_b = RealmId::new([2; 16]);
    db.set_realm_quotas(
        realm_a,
        RealmQuotas {
            max_segment_bytes: Some(20_000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    let meta_a = create_segment_of_size(&db, realm_a, 1).await;
    let meta_b = create_segment_of_size(&db, realm_b, 5).await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.link_segment("a", &meta_a).await.unwrap();
        w.commit().await.unwrap();
    }
    // realm_b has no quota so the larger segment links fine.
    let mut w = db.begin_write().await.unwrap();
    w.link_segment("b", &meta_b).await.unwrap();
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn replace_segment_within_quota_succeeds() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    db.set_realm_quotas(
        realm,
        RealmQuotas {
            max_segment_bytes: Some(50_000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    let meta1 = create_segment_of_size(&db, realm, 5).await;
    {
        let mut w = db.begin_write().await.unwrap();
        w.link_segment("name", &meta1).await.unwrap();
        w.commit().await.unwrap();
    }
    let meta2 = create_segment_of_size(&db, realm, 5).await;
    let mut w = db.begin_write().await.unwrap();
    w.replace_segment("name", &meta2).await.unwrap();
    w.commit().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn replace_segment_over_quota_rejected() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    db.set_realm_quotas(
        realm,
        RealmQuotas {
            max_segment_bytes: Some(20_000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    let meta1 = create_segment_of_size(&db, realm, 1).await; // small
    {
        let mut w = db.begin_write().await.unwrap();
        w.link_segment("name", &meta1).await.unwrap();
        w.commit().await.unwrap();
    }
    let meta2 = create_segment_of_size(&db, realm, 10).await; // big
    let mut w = db.begin_write().await.unwrap();
    let err = w.replace_segment("name", &meta2).await.err().unwrap();
    assert!(matches!(
        err,
        PagedbError::Quota {
            kind: QuotaKind::SegmentBytes,
            ..
        }
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn quota_default_after_unset() {
    let db = open().await;
    let realm = RealmId::new([1; 16]);
    db.set_realm_quotas(
        realm,
        RealmQuotas {
            max_segment_bytes: Some(20_000),
            ..RealmQuotas::default()
        },
    )
    .await
    .unwrap();
    // Remove the cap.
    db.set_realm_quotas(realm, RealmQuotas::default())
        .await
        .unwrap();
    let meta = create_segment_of_size(&db, realm, 20).await;
    let mut w = db.begin_write().await.unwrap();
    w.link_segment("any", &meta).await.unwrap();
    w.commit().await.unwrap();
}
