// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wall-clock access.
//!
//! `wasm32-unknown-unknown` has no std clock: `SystemTime::now()` panics with
//! "time not implemented on this platform". The OPFS build reads the host
//! clock through `js_sys` instead; every other target, `wasm32-wasip1`
//! included, uses std.
//!
//! A wasm build *without* the JS bindings has no clock at all, and that case is
//! represented rather than papered over: [`unix_seconds`] returns `None`, and
//! [`clock_available`] lets a caller refuse a policy that a frozen clock would
//! silently neuter. Returning `0` instead would be worse than useless — the
//! commit-history ordering tolerates a zero timestamp, but the age-based
//! retention policy reads it as "nothing is older than the threshold" and stops
//! pruning, so `RetainPolicy::Age` would quietly behave as `Unbounded`.

/// Seconds since the Unix epoch, or `None` when this build has no clock.
///
/// `None` on `wasm32-unknown-unknown` without the `opfs` feature. Every other
/// target answers, `wasm32-wasip1` included.
#[cfg(all(target_arch = "wasm32", target_os = "unknown", feature = "opfs"))]
pub(crate) fn unix_seconds() -> Option<u64> {
    Some((js_sys::Date::now() / 1000.0) as u64)
}

/// No clock in this configuration: `wasm32-unknown-unknown` without the JS
/// bindings. Callers either tolerate the absence (commit-history ordering keeps
/// its total order without timestamps) or refuse the configuration up front
/// (age retention) — see [`clock_available`].
#[cfg(all(target_arch = "wasm32", target_os = "unknown", not(feature = "opfs")))]
pub(crate) fn unix_seconds() -> Option<u64> {
    None
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
// Clippy sees only this arm's body, where the answer is always `Some`, and
// calls the wrapper unnecessary. It is not: the `wasm32-unknown-unknown` arm
// above returns `None`, and one signature across the three arms is what lets a
// caller ask "is there a clock" without a second, drift-prone cfg.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn unix_seconds() -> Option<u64> {
    Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

/// Whether this build can read a wall clock at all.
///
/// A caller that needs time to *mean* something refuses its configuration when
/// this is false; a caller that only needs a total order can read
/// [`unix_seconds`]'s absence as "no timestamp".
pub(crate) const fn clock_available() -> bool {
    cfg!(not(all(
        target_arch = "wasm32",
        target_os = "unknown",
        not(feature = "opfs")
    )))
}

// The three arms above are selected by a cfg triple, and a cfg that is always
// true compiles into a configuration nobody builds. This pins the direction a
// build can get wrong silently: a `wasm32-unknown-unknown` build without the JS
// bindings that reports a clock anyway, which would leave `Age` unrefused. The
// other direction — `opfs` present, clock absent — is caught at runtime by the
// smoke tests, which commit under age retention on exactly that build. Both
// configurations are compiled in CI: `wasm-smoke` brings `opfs`, and
// `wasm-smoke-no-clock` is the build that has none.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const _: () = assert!(
    cfg!(feature = "opfs") || !clock_available(),
    "a wasm32-unknown-unknown build without `opfs` must report no clock"
);
