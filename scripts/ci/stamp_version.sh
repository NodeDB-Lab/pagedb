#!/usr/bin/env bash
# Stamp Cargo.toml's package version from a validated release tag.
#
#   scripts/ci/stamp_version.sh <version>  # e.g. 0.1.0, 0.1.0-beta.3
#
# PageDB is one publishable crate. Its workspace lockfile also records the root
# package version because the benchmark child package depends on PageDB by path.

set -euo pipefail

VERSION="${1:?usage: stamp_version.sh <version>}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z][A-Za-z0-9-]*\.[0-9]+)?$ ]]; then
  printf 'invalid version %q; expected X.Y.Z or X.Y.Z-label.N\n' "$VERSION" >&2
  exit 2
fi

CURRENT="$(
  cargo metadata --no-deps --format-version=1 |
    jq -r '.packages[] | select(.name == "pagedb") | .version'
)"
test -n "$CURRENT" || {
  printf 'could not resolve the package version from Cargo.toml\n' >&2
  exit 1
}

manifest='Cargo.toml'
lockfile='Cargo.lock'
test -f "$lockfile" || {
  printf 'missing %s; release stamping requires the tracked lockfile\n' "$lockfile" >&2
  exit 1
}

temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
manifest_backup="$(mktemp "${manifest}.backup.XXXXXX")"
lock_backup="$(mktemp "${lockfile}.backup.XXXXXX")"
cleanup() {
  rm -f -- "$temporary" "$manifest_backup" "$lock_backup"
}
trap cleanup EXIT
cp -p -- "$manifest" "$temporary"
cp -p -- "$manifest" "$manifest_backup"
cp -p -- "$lockfile" "$lock_backup"

if [[ "$VERSION" != "$CURRENT" ]]; then
  awk -v version="$VERSION" '
    BEGIN {
      in_package = 0
      replaced = 0
    }
    /^\[package\][[:space:]]*$/ {
      in_package = 1
      print
      next
    }
    /^\[/ {
      in_package = 0
    }
    in_package && /^[[:space:]]*version[[:space:]]*=/ {
      if (replaced) {
        exit 42
      }
      print "version = \"" version "\""
      replaced = 1
      next
    }
    {
      print
    }
    END {
      if (!replaced) {
        exit 43
      }
    }
  ' "$manifest" >"$temporary" || {
    printf 'could not replace [package] version in %s\n' "$manifest" >&2
    exit 1
  }
  mv -- "$temporary" "$manifest"
fi

if ! cargo update --quiet -p pagedb --precise "$VERSION" --offline; then
  cp -p -- "$manifest_backup" "$manifest"
  cp -p -- "$lock_backup" "$lockfile"
  printf 'could not align %s with package version %s\n' "$lockfile" "$VERSION" >&2
  exit 1
fi

if [[ "$VERSION" == "$CURRENT" ]]; then
  printf 'Version already %s - manifest and lockfile aligned.\n' "$VERSION"
else
  printf 'Stamped package version: %s -> %s\n' "$CURRENT" "$VERSION"
fi

trap - EXIT
cleanup
