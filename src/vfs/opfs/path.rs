//! Pure path helpers for the OPFS VFS root-prefixing scheme.
//!
//! The OPFS backend only compiles for `wasm32 + opfs`, but the rooting logic is
//! plain string manipulation. Keeping it here as target-independent free
//! functions lets it be unit-tested on the host even though the rest of the
//! backend cannot be. `OpfsVfs` (wasm) is the sole production caller, so on
//! every other target these are legitimately dead — hence the `allow`.

/// Normalise a caller-supplied root directory into a single leading-slash
/// prefix, or the empty string when no rooting is requested.
///
/// Surrounding slashes are trimmed: `"db"`, `"/db"`, and `"/db/"` all map to
/// `"/db"`; `""`, `"/"`, and `"///"` map to `""` (legacy origin-root layout).
#[cfg_attr(not(all(target_arch = "wasm32", feature = "opfs")), allow(dead_code))]
pub(super) fn normalize_root(root: &str) -> String {
    let trimmed = root.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
    }
}

/// Join a virtual VFS path under a normalised root.
///
/// pagedb hands the VFS origin-relative *virtual* paths (e.g. `/main.db`); the
/// native `TokioVfs` joins them onto its on-disk root the same way. The leading
/// `/` is stripped and the remainder joined under `root` with exactly one
/// separator, so the result is correct whether `path` arrives absolute
/// (`/main.db`) or relative (`main.db`) — it never glues into `/dbmain.db`. An
/// empty `root` returns `path` unchanged, preserving the legacy layout exactly.
#[cfg_attr(not(all(target_arch = "wasm32", feature = "opfs")), allow(dead_code))]
pub(super) fn join_root(root: &str, path: &str) -> String {
    if root.is_empty() {
        path.to_string()
    } else {
        format!("{}/{}", root, path.trim_start_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_surrounding_slashes() {
        assert_eq!(normalize_root("db"), "/db");
        assert_eq!(normalize_root("/db"), "/db");
        assert_eq!(normalize_root("/db/"), "/db");
        assert_eq!(normalize_root("a/b"), "/a/b");
    }

    #[test]
    fn normalize_empty_or_slash_only_means_no_root() {
        assert_eq!(normalize_root(""), "");
        assert_eq!(normalize_root("/"), "");
        assert_eq!(normalize_root("///"), "");
    }

    #[test]
    fn join_uses_single_separator_regardless_of_leading_slash() {
        // Absolute virtual path — how pagedb actually calls the VFS.
        assert_eq!(join_root("/db", "/main.db"), "/db/main.db");
        // Relative virtual path — must NOT glue into "/dbmain.db".
        assert_eq!(join_root("/db", "main.db"), "/db/main.db");
        // Nested segments are preserved.
        assert_eq!(join_root("/db", "/segments/seg-1"), "/db/segments/seg-1");
    }

    #[test]
    fn empty_root_passes_path_through_unchanged() {
        assert_eq!(join_root("", "/main.db"), "/main.db");
        assert_eq!(join_root("", "main.db"), "main.db");
    }

    #[test]
    fn distinct_roots_never_collide_on_the_fixed_main_db_path() {
        let a = join_root(&normalize_root("alpha"), "/main.db");
        let b = join_root(&normalize_root("beta"), "/main.db");
        assert_eq!(a, "/alpha/main.db");
        assert_eq!(b, "/beta/main.db");
        assert_ne!(a, b);
    }
}
