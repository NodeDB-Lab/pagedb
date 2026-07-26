// SPDX-License-Identifier: MIT OR Apache-2.0

//! Black-box diagnostics wiring.
//!
//! Thin, always-callable shims over the `blackbox` recorder: breadcrumbs on the
//! significant operations (commit, reopen) and a structured corruption report
//! at the page read-verify failure site — the exact place a freed-page
//! use-after-free surfaces as an AEAD/MAC failure.
//!
//! The real implementation is compiled only under the `diagnostics` feature and
//! off wasm32; otherwise every entry point is a no-op with the same signature,
//! so call sites never need `cfg`. Reports are inert until the host application
//! calls [`blackbox::init`], so a library emitting these costs nothing on its
//! own.

#[cfg(all(feature = "diagnostics", not(target_arch = "wasm32")))]
mod imp {
    use crate::RealmId;

    /// Breadcrumb: a store was (re)opened — marks epoch boundaries in the trail,
    /// the dimension along which freed-page use-after-free surfaces.
    pub fn reopened(latest_commit: u64) {
        blackbox::breadcrumb!(Info, "pagedb.reopen", "opened store", { "latest_commit": latest_commit });
    }

    /// Breadcrumb: a commit was published, with the number of pages it freed —
    /// the operations most implicated in page recycling.
    pub fn committed(commit_id: u64, freed_pages: usize) {
        blackbox::breadcrumb!(Debug, "pagedb.commit", "committed", {
            "commit_id": commit_id,
            "freed_pages": freed_pages,
        });
    }

    /// Breadcrumb: a sentinel lock (writer, frozen-reader, or observer) was
    /// acquired at open — marks who holds exclusivity over a store.
    pub fn lock_acquired(mode: &str, path: &str) {
        blackbox::breadcrumb!(Info, "pagedb.lock_acquired", "sentinel lock acquired", {
            "mode": mode,
            "path": path,
        });
    }

    /// Breadcrumb: a sentinel lock acquisition was rejected — a concurrent
    /// open lost the race, so the failure has a trail even though it never
    /// touched the store.
    pub fn lock_rejected(mode: &str, path: &str, reason: &str) {
        blackbox::breadcrumb!(Info, "pagedb.lock_rejected", "sentinel lock rejected", {
            "mode": mode,
            "path": path,
            "reason": reason,
        });
    }

    /// Breadcrumb: dirty pages were flushed and fsynced to durable storage.
    pub fn flushed(bytes: u64) {
        blackbox::breadcrumb!(Debug, "pagedb.flushed", "flushed to disk", {
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

    impl blackbox::DomainContext for PageReadVerifyFailure {
        fn domain_kind(&self) -> &'static str {
            "pagedb.page_read_verify_failure"
        }
        fn grouping_key(&self) -> String {
            // Group by (file, expected binding), NOT the specific page id, so
            // instances of one structural bug collapse together.
            format!("file={};binding={}", self.file, self.binding)
        }
        fn to_json(&self) -> blackbox::serde_json::Value {
            blackbox::serde_json::json!({
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
    pub fn page_read_verify_failed(
        main_db_path: &str,
        page_id: u64,
        file: &str,
        binding: &str,
        realm: &RealmId,
    ) {
        let ctx = PageReadVerifyFailure {
            page_id,
            file: file.to_owned(),
            binding: binding.to_owned(),
            realm_hex: crate::hex::to_hex_lower(&realm.0),
            main_db_path: main_db_path.to_owned(),
        };
        let _ = blackbox::Capture::new(
            blackbox::EventKind::Corruption,
            "page AEAD/MAC verification failed on read",
        )
        .domain(&ctx)
        .with_backtrace()
        .emit();
    }
}

#[cfg(not(all(feature = "diagnostics", not(target_arch = "wasm32"))))]
mod imp {
    use crate::RealmId;

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
    ) {
    }
}

pub use imp::{committed, flushed, lock_acquired, lock_rejected, page_read_verify_failed, reopened};

/// Convenience for call sites that hold `Debug`-only types: format a value for
/// a report field. Kept here so the (rare, failure-path-only) allocation is
/// obviously intentional.
#[must_use]
pub fn dbg_str<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
}
