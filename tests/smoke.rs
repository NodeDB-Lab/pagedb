use pagedb::errors::{CorruptionDetail, Evictable, PagedbError, QuotaKind};
use pagedb::{CommitId, RealmId};

#[test]
fn corruption_constructor_round_trips() {
    let err = PagedbError::corruption(CorruptionDetail::FooterUnverifiable {
        realm_id: RealmId::new([0u8; 16]),
        name: "engine.idx".into(),
        segment_id: [1u8; 16],
    });
    assert!(matches!(err, PagedbError::Corruption(_)));
    let _ = format!("{err}");
    let _ = format!("{err:?}");
}

#[test]
fn quota_constructor_round_trips() {
    let err = PagedbError::quota(RealmId::new([0u8; 16]), QuotaKind::SegmentBytes, 1024, 512);
    if let PagedbError::Quota {
        kind, used, limit, ..
    } = err
    {
        assert_eq!(kind, QuotaKind::SegmentBytes);
        assert_eq!(used, 1024);
        assert_eq!(limit, 512);
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn io_error_from_conversion() {
    let io = std::io::Error::other("disk wobble");
    let err: PagedbError = io.into();
    assert!(matches!(err, PagedbError::Io(_)));
}

#[test]
fn every_variant_displays() {
    let realm = RealmId::new([0u8; 16]);
    let cases: Vec<PagedbError> = vec![
        PagedbError::ChecksumFailure,
        PagedbError::corruption(CorruptionDetail::HeaderUnverifiable),
        PagedbError::corruption(CorruptionDetail::ForeignSegment {
            realm_id: realm,
            name: "x".into(),
            segment_id: [0; 16],
            footer_parent_file_id: [1; 16],
            expected_parent_file_id: [2; 16],
        }),
        PagedbError::corruption(CorruptionDetail::SegmentMissing {
            realm_id: realm,
            name: "x".into(),
            segment_id: [0; 16],
        }),
        PagedbError::corruption(CorruptionDetail::StagingMissing {
            realm_id: realm,
            name: "x".into(),
            segment_id: [0; 16],
        }),
        PagedbError::corruption(CorruptionDetail::PageUnverifiable {
            realm_id: realm,
            segment_id: Some([0; 16]),
            page_id: 42,
            evictable: Some(Evictable::Replaceable),
        }),
        PagedbError::corruption(CorruptionDetail::ManifestUnverifiable {
            realm_id: realm,
            segment_id: [0; 16],
        }),
        PagedbError::quota(realm, QuotaKind::Pages, 1, 0),
        PagedbError::NoSpace,
        PagedbError::ReadOnly,
        PagedbError::WriterPresent,
        PagedbError::ReadersPresent,
        PagedbError::AlreadyOpen,
        PagedbError::AlreadyLocked,
        PagedbError::RestoredNotPromoted,
        PagedbError::IdentityForked,
        PagedbError::CommitGone {
            commit: CommitId::new(10),
            oldest_available: CommitId::new(20),
        },
        PagedbError::NotFound,
        PagedbError::AlreadyLinked,
        PagedbError::NotLinked,
        PagedbError::NameTooLong,
        PagedbError::IllegalPageKind,
        PagedbError::PayloadTooLarge,
        PagedbError::ManifestTooLarge,
        PagedbError::MmapViewQuotaExceeded {
            segment_bytes: 100,
            available_bytes: 50,
        },
        PagedbError::Aborted,
        PagedbError::FreeListExhausted,
        PagedbError::SegmentTombstoneStalled,
        PagedbError::ReadersPinningTruncatedRange,
        PagedbError::Unsupported,
    ];
    for c in &cases {
        let _ = format!("{c}");
        let _ = format!("{c:?}");
    }
}
