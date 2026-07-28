// SPDX-License-Identifier: MIT OR Apache-2.0

//! Black-box diagnostics wiring.
//!
//! Thin, always-callable shims over the `faultbox` recorder: breadcrumbs on the
//! significant operations (commit, reopen) and a structured corruption report
//! at the page read-verify failure site — the exact place a freed-page
//! use-after-free surfaces as an AEAD/MAC failure.
//!
//! The real implementation is compiled only under the `diagnostics` feature and
//! off wasm32; otherwise every entry point is a no-op with the same signature,
//! so call sites never need `cfg`. Reports are inert until the host application
//! calls [`faultbox::init`], so a library emitting these costs nothing on its
//! own.

#[cfg(all(feature = "diagnostics", not(target_arch = "wasm32")))]
mod imp {
    use std::cell::Cell;
    use std::marker::PhantomData;

    use crate::RealmId;
    use crate::errors::CorruptionDetail;

    thread_local! {
        /// Live [`RichlyReported`] guards on this thread. A depth rather than a
        /// flag: nesting must not leave the suppression stuck on when the inner
        /// guard drops.
        static RICH_REPORTS_IN_FLIGHT: Cell<u32> = const { Cell::new(0) };
    }

    /// Evidence that a site-specific report already covers the corruption about
    /// to be constructed.
    ///
    /// Every rich capture in this module returns one. Bind it across the
    /// `PagedbError::corruption(...)` call that reports the same failure and
    /// [`corruption_captured`] stands down for that construction, so one
    /// failure files one report — the site's, which carries forensics (the
    /// failing page, the fsck hint, the store path) that the constructor, which
    /// sees only a `CorruptionDetail`, cannot know.
    ///
    /// This is the mechanism, not a special case: a second site that grows its
    /// own `DomainContext` gets the same suppression by returning this type
    /// from its capture function, with nothing to rediscover.
    ///
    /// Deliberately not `Send`. The guard covers the construction immediately
    /// following it and nothing else; holding it across an `.await` would
    /// silence unrelated corruption raised by whatever ran in between, and the
    /// compiler rejects that wherever the surrounding future must be `Send`.
    #[must_use = "bind the guard so it outlives the corruption() call it covers"]
    pub struct RichlyReported {
        _not_send: PhantomData<*const ()>,
    }

    impl RichlyReported {
        fn begin() -> Self {
            RICH_REPORTS_IN_FLIGHT.with(|depth| depth.set(depth.get().saturating_add(1)));
            Self {
                _not_send: PhantomData,
            }
        }
    }

    impl Drop for RichlyReported {
        fn drop(&mut self) {
            RICH_REPORTS_IN_FLIGHT.with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }

    /// Breadcrumb: a store was (re)opened — marks epoch boundaries in the trail,
    /// the dimension along which freed-page use-after-free surfaces.
    pub fn reopened(latest_commit: u64) {
        faultbox::breadcrumb!(Info, "pagedb.reopen", "opened store", { "latest_commit": latest_commit });
    }

    /// Breadcrumb: a commit was published, with the number of pages it freed —
    /// the operations most implicated in page recycling.
    pub fn committed(commit_id: u64, freed_pages: usize) {
        faultbox::breadcrumb!(Debug, "pagedb.commit", "committed", {
            "commit_id": commit_id,
            "freed_pages": freed_pages,
        });
    }

    /// Breadcrumb: a sentinel lock (writer, frozen-reader, or observer) was
    /// acquired at open — marks who holds exclusivity over a store.
    pub fn lock_acquired(mode: &str, path: &str) {
        faultbox::breadcrumb!(Info, "pagedb.lock_acquired", "sentinel lock acquired", {
            "mode": mode,
            "path": path,
        });
    }

    /// Breadcrumb: a sentinel lock acquisition was rejected — a concurrent
    /// open lost the race, so the failure has a trail even though it never
    /// touched the store.
    pub fn lock_rejected(mode: &str, path: &str, reason: &str) {
        faultbox::breadcrumb!(Info, "pagedb.lock_rejected", "sentinel lock rejected", {
            "mode": mode,
            "path": path,
            "reason": reason,
        });
    }

    /// Breadcrumb: dirty pages were flushed and fsynced to durable storage.
    pub fn flushed(bytes: u64) {
        faultbox::breadcrumb!(Debug, "pagedb.flushed", "flushed to disk", {
            "bytes": bytes,
        });
    }

    /// Forensic context for a page that failed AEAD/MAC verification on read —
    /// mirrors what `pagedb-fsck` would report for the same page.
    struct PageReadVerifyFailure {
        page_id: u64,
        file: String,
        binding: String,
        realm_hex: String,
        main_db_path: String,
    }

    impl faultbox::DomainContext for PageReadVerifyFailure {
        fn domain_kind(&self) -> &'static str {
            "pagedb.page_read_verify_failure"
        }
        fn grouping_key(&self) -> String {
            // Group by (file, expected binding), NOT the specific page id, so
            // instances of one structural bug collapse together.
            format!("file={};binding={}", self.file, self.binding)
        }
        fn to_json(&self) -> faultbox::serde_json::Value {
            faultbox::serde_json::json!({
                "page_id": self.page_id,
                "file": self.file,
                "binding": self.binding,
                "realm": self.realm_hex,
                // VFS-relative store path. Preserving the store for offline
                // `pagedb-fsck` is the host application's job — only it knows
                // the real on-disk directory behind the VFS.
                "main_db_path": self.main_db_path,
                "fsck_hint": format!("pagedb-fsck <store-dir> --deep --realm {}", self.realm_hex),
            })
        }
    }

    /// Capture a structured corruption report for a page that would not
    /// authenticate. Records the failing page, expected binding, and realm so
    /// the failure is diagnosable from the report alone; the host application
    /// preserves the store bytes (it owns the real path behind the VFS).
    ///
    /// Returns a [`RichlyReported`] guard: bind it across the
    /// `PagedbError::corruption(...)` that turns this same failure into an
    /// error, so the caller gets the precise variant while this report — not
    /// the constructor's generic one — is what gets filed.
    pub fn page_read_verify_failed(
        main_db_path: &str,
        page_id: u64,
        file: &str,
        binding: &str,
        realm: &RealmId,
    ) -> RichlyReported {
        let ctx = PageReadVerifyFailure {
            page_id,
            file: file.to_owned(),
            binding: binding.to_owned(),
            realm_hex: crate::hex::to_hex_lower(&realm.0),
            main_db_path: main_db_path.to_owned(),
        };
        let _ = faultbox::Capture::new(
            faultbox::EventKind::Corruption,
            "page AEAD/MAC verification failed on read",
        )
        .domain(&ctx)
        .with_backtrace()
        .emit();
        RichlyReported::begin()
    }

    /// Forensic context for a [`CorruptionDetail`] captured at the moment
    /// `PagedbError::corruption()` constructs it — the one funnel every
    /// `CorruptionDetail` variant passes through.
    struct CorruptionConstructed {
        /// Stable per-variant identifier, independent of the instance's field
        /// values, so `faultbox`'s domain-kind bucket is the failure *mode*.
        kind: &'static str,
        /// Coalescing key: variant name plus whichever fields identify the
        /// structural bug rather than the specific instance (never a raw
        /// `page_id`/`segment_id`/counter alone) — the same grouping
        /// discipline `PageReadVerifyFailure` already uses, so one bug landed
        /// once still collapses to one report under fuzzing.
        grouping_key: String,
        /// `Debug` rendering of the detail, for a report that is diagnosable
        /// on its own — with embedder-chosen text redacted. A report may be
        /// shipped to crash telemetry, and a segment name is application data
        /// (a tenant id, a user's collection name) that diagnosis never needs:
        /// the identity that locates the file is the `segment_id`, which is
        /// kept. See [`redacted_debug`].
        detail_debug: String,
    }

    impl faultbox::DomainContext for CorruptionConstructed {
        fn domain_kind(&self) -> &'static str {
            self.kind
        }
        fn grouping_key(&self) -> String {
            self.grouping_key.clone()
        }
        fn to_json(&self) -> faultbox::serde_json::Value {
            faultbox::serde_json::json!({ "detail": self.detail_debug })
        }
    }

    /// Render a [`CorruptionDetail`] for a report, replacing any
    /// embedder-chosen string with its length.
    ///
    /// Every field in the taxonomy is either a `&'static str` this crate
    /// wrote, a numeric id, or a raw identity — none of which is application
    /// data — except the segment `name` carried by
    /// [`CorruptionDetail::SegmentMissing`], which is whatever the embedder
    /// passed to `link_segment`. That one is replaced here rather than
    /// suppressed at the call site, so a future variant that adds a name gets
    /// the same treatment by extending this one function.
    fn redacted_debug(detail: &CorruptionDetail) -> String {
        match detail {
            CorruptionDetail::SegmentMissing {
                realm_id,
                name,
                segment_id,
            } => format!(
                "SegmentMissing {{ realm_id: {realm_id:?}, name: <redacted, {} bytes>, \
                 segment_id: {segment_id:?} }}",
                name.len()
            ),
            other => format!("{other:?}"),
        }
    }

    /// Classify a [`CorruptionDetail`] into a stable domain kind and a
    /// grouping key that names the structural fields of the failure but never
    /// the instance-specific ones (page ids, segment ids), so many
    /// occurrences of one bug — the common shape under fuzzing — coalesce
    /// into one report instead of one per occurrence.
    fn classify(detail: &CorruptionDetail) -> (&'static str, String) {
        match detail {
            CorruptionDetail::ForeignSegment { .. } => (
                "pagedb.corruption.foreign_segment",
                "ForeignSegment".to_owned(),
            ),
            CorruptionDetail::FooterUnverifiable { .. } => (
                "pagedb.corruption.footer_unverifiable",
                "FooterUnverifiable".to_owned(),
            ),
            CorruptionDetail::SegmentMetadataMismatch { field } => (
                "pagedb.corruption.segment_metadata_mismatch",
                format!("SegmentMetadataMismatch:field={field}"),
            ),
            CorruptionDetail::SegmentGeometryInvalid { field } => (
                "pagedb.corruption.segment_geometry_invalid",
                format!("SegmentGeometryInvalid:field={field}"),
            ),
            CorruptionDetail::CatalogRowInvalid { field } => (
                "pagedb.corruption.catalog_row_invalid",
                format!("CatalogRowInvalid:field={field}"),
            ),
            CorruptionDetail::SegmentMissing { .. } => (
                "pagedb.corruption.segment_missing",
                "SegmentMissing".to_owned(),
            ),
            CorruptionDetail::StagingMissing { .. } => (
                "pagedb.corruption.staging_missing",
                "StagingMissing".to_owned(),
            ),
            CorruptionDetail::PageUnverifiable { .. } => (
                "pagedb.corruption.page_unverifiable",
                "PageUnverifiable".to_owned(),
            ),
            CorruptionDetail::ManifestUnverifiable { .. } => (
                "pagedb.corruption.manifest_unverifiable",
                "ManifestUnverifiable".to_owned(),
            ),
            CorruptionDetail::HeaderUnverifiable => (
                "pagedb.corruption.header_unverifiable",
                "HeaderUnverifiable".to_owned(),
            ),
            CorruptionDetail::StructuralHeaderInvalid { header, field } => (
                "pagedb.corruption.structural_header_invalid",
                format!("StructuralHeaderInvalid:header={header}:field={field}"),
            ),
            CorruptionDetail::FooterFramingInvalid { field } => (
                "pagedb.corruption.footer_framing_invalid",
                format!("FooterFramingInvalid:field={field}"),
            ),
            CorruptionDetail::NodeBodyMalformed { field } => (
                "pagedb.corruption.node_body_malformed",
                format!("NodeBodyMalformed:field={field}"),
            ),
            CorruptionDetail::NodeKindMismatch {
                expected, found, ..
            } => (
                "pagedb.corruption.node_kind_mismatch",
                format!("NodeKindMismatch:expected={expected}:found={found}"),
            ),
            CorruptionDetail::OverflowBodyMalformed { field } => (
                "pagedb.corruption.overflow_body_malformed",
                format!("OverflowBodyMalformed:field={field}"),
            ),
            CorruptionDetail::JournalRecordMalformed { field } => (
                "pagedb.corruption.journal_record_malformed",
                format!("JournalRecordMalformed:field={field}"),
            ),
            CorruptionDetail::SnapshotArtifactInvalid { field } => (
                "pagedb.corruption.snapshot_artifact_invalid",
                format!("SnapshotArtifactInvalid:field={field}"),
            ),
            CorruptionDetail::ReservedPageReferenced { .. } => (
                "pagedb.corruption.reserved_page_referenced",
                "ReservedPageReferenced".to_owned(),
            ),
            CorruptionDetail::OverflowChainCycle { .. } => (
                "pagedb.corruption.overflow_chain_cycle",
                "OverflowChainCycle".to_owned(),
            ),
            CorruptionDetail::PageChainCycle { structure, .. } => (
                "pagedb.corruption.page_chain_cycle",
                format!("PageChainCycle:structure={structure}"),
            ),
            CorruptionDetail::LeafSiblingMismatch { .. } => (
                "pagedb.corruption.leaf_sibling_mismatch",
                "LeafSiblingMismatch".to_owned(),
            ),
            CorruptionDetail::PageKindAliased {
                walked_as,
                referenced_as,
                ..
            } => (
                "pagedb.corruption.page_kind_aliased",
                format!("PageKindAliased:walked_as={walked_as}:referenced_as={referenced_as}"),
            ),
            // `CorruptionDetail` is `#[non_exhaustive]`: within this crate that
            // only guards against missing a match arm when a variant is added,
            // not against external construction, so a catch-all still reports
            // *something* rather than silently dropping a future variant.
            #[allow(unreachable_patterns)]
            _ => ("pagedb.corruption.other", "Other".to_owned()),
        }
    }

    /// Capture a structured corruption report at the moment a
    /// [`CorruptionDetail`] is constructed — called from
    /// `PagedbError::corruption()`, the single funnel every variant passes
    /// through, so every precise diagnosis in the taxonomy reaches the
    /// reporting layer instead of only the one AEAD failure site this module
    /// originally covered.
    pub fn corruption_captured(detail: &CorruptionDetail) {
        // A site-specific capture is already in flight for this exact failure
        // and carries strictly more than this one could. Filing both would mean
        // two reports for one event, the second of them less useful.
        if RICH_REPORTS_IN_FLIGHT.with(Cell::get) > 0 {
            return;
        }
        let (kind, grouping_key) = classify(detail);
        let ctx = CorruptionConstructed {
            kind,
            grouping_key,
            detail_debug: redacted_debug(detail),
        };
        let _ = faultbox::Capture::new(
            faultbox::EventKind::Corruption,
            "corruption detail constructed",
        )
        .domain(&ctx)
        .with_backtrace()
        .emit();
    }
}

#[cfg(not(all(feature = "diagnostics", not(target_arch = "wasm32"))))]
mod imp {
    use crate::RealmId;

    /// No-op counterpart of the recording build's suppression guard, so call
    /// sites bind the same value under every cfg.
    pub struct RichlyReported;

    pub fn reopened(_latest_commit: u64) {}
    pub fn committed(_commit_id: u64, _freed_pages: usize) {}
    pub fn lock_acquired(_mode: &str, _path: &str) {}
    pub fn lock_rejected(_mode: &str, _path: &str, _reason: &str) {}
    pub fn flushed(_bytes: u64) {}
    pub fn page_read_verify_failed(
        _main_db_path: &str,
        _page_id: u64,
        _file: &str,
        _binding: &str,
        _realm: &RealmId,
    ) -> RichlyReported {
        RichlyReported
    }

    pub fn corruption_captured(_detail: &crate::errors::CorruptionDetail) {}
}

// `RichlyReported` is deliberately not re-exported: a call site binds it as the
// return value of a rich capture (`let _report = diag::page_read_verify_failed(…)`)
// and never names the type, so exporting it would only be an unused path.
pub use imp::{
    committed, corruption_captured, flushed, lock_acquired, lock_rejected, page_read_verify_failed,
    reopened,
};

/// Convenience for call sites that hold `Debug`-only types: format a value for
/// a report field. Kept here so the (rare, failure-path-only) allocation is
/// obviously intentional.
#[must_use]
pub fn dbg_str<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
}
