// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wall-clock access.
//!
//! `wasm32-unknown-unknown` has no std clock: `SystemTime::now()` panics with
//! "time not implemented on this platform". The OPFS build reads the host
//! clock through `js_sys` instead; a wasm build without that feature degrades
//! to `0` rather than panicking. Every other target, `wasm32-wasip1`
//! included, uses std.

/// Seconds since the Unix epoch.
///
/// Feeds the commit-history timestamp and the age-based retention threshold.
/// A `0` (no clock in this configuration) keeps both ordered by commit
/// sequence instead of inventing a time.
#[cfg(all(target_arch = "wasm32", target_os = "unknown", feature = "opfs"))]
pub(crate) fn unix_seconds() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// No clock in this configuration: `wasm32-unknown-unknown` without the JS
/// bindings. Callers get `0`, which the commit-history ordering tolerates.
#[cfg(all(target_arch = "wasm32", target_os = "unknown", not(feature = "opfs")))]
pub(crate) fn unix_seconds() -> u64 {
    0
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
