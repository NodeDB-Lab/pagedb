#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'stamp version contract: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_script="$repo_root/scripts/ci/stamp_version.sh"
test -f "$source_script" || die "missing scripts/ci/stamp_version.sh"

fixture="$(mktemp -d "${TMPDIR:-/tmp}/pagedb-stamp-version.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/consumer/src" "$fixture/scripts/ci" "$fixture/src"
cp "$source_script" "$fixture/scripts/ci/stamp_version.sh"

cat >"$fixture/Cargo.toml" <<'TOML'
[workspace]
members = ["consumer"]
resolver = "3"

[package]
name = "pagedb"
version = "0.1.0"
edition = "2024"

[package.metadata.fixture]
version = "9.9.9"
TOML

cat >"$fixture/src/lib.rs" <<'RUST'
pub fn fixture() {}
RUST

cat >"$fixture/consumer/Cargo.toml" <<'TOML'
[package]
name = "pagedb-stamp-consumer"
version = "0.0.0"
edition = "2024"

[dependencies]
pagedb = { path = ".." }
TOML

cat >"$fixture/consumer/src/lib.rs" <<'RUST'
pub fn fixture() {
    pagedb::fixture();
}
RUST

(
  cd "$fixture"
  cargo generate-lockfile --quiet --offline
)

run_stamp() {
  (
    cd "$fixture"
    bash scripts/ci/stamp_version.sh "$@"
  )
}

file_mode() {
  stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"
}

original_mode="$(file_mode "$fixture/Cargo.toml")"
run_stamp 0.1.0 | grep -F 'Version already 0.1.0' >/dev/null ||
  die "same-version run is not an explicit no-op"

run_stamp 0.1.0-beta.3 | grep -F 'Stamped package version: 0.1.0 -> 0.1.0-beta.3' >/dev/null ||
  die "valid prerelease version was not stamped"
grep -F 'version = "0.1.0-beta.3"' "$fixture/Cargo.toml" >/dev/null ||
  die "package version did not change"
grep -F 'version = "9.9.9"' "$fixture/Cargo.toml" >/dev/null ||
  die "metadata version was changed with the package version"
test "$(file_mode "$fixture/Cargo.toml")" = "$original_mode" ||
  die "stamping changed Cargo.toml permissions"
test "$(
  cd "$fixture"
  cargo metadata --locked --no-deps --format-version=1 |
    jq -r '.packages[] | select(.name == "pagedb") | .version'
)" = '0.1.0-beta.3' || die "Cargo does not observe the stamped prerelease"
test "$(
  awk '
    /^\[\[package\]\]$/ { in_pagedb = 0 }
    /^name = "pagedb"$/ { in_pagedb = 1; next }
    in_pagedb && /^version = / {
      gsub(/^version = "|"$|"/, "")
      print
      exit
    }
  ' "$fixture/Cargo.lock"
)" = '0.1.0-beta.3' || die "workspace lockfile did not receive the stamped version"
(
  cd "$fixture"
  cargo package --quiet --locked --allow-dirty --no-verify --offline
) || die "stamped prerelease does not support a locked package build"

before="$(shasum -a 256 "$fixture/Cargo.toml" | awk '{print $1}')"
run_stamp 0.1.0-beta.3 | grep -F 'Version already 0.1.0-beta.3' >/dev/null ||
  die "repeated prerelease run is not idempotent"
after="$(shasum -a 256 "$fixture/Cargo.toml" | awk '{print $1}')"
test "$before" = "$after" || die "idempotent run rewrote Cargo.toml"

cp "$fixture/Cargo.lock" "$fixture/Cargo.lock.valid"
printf 'not a cargo lockfile\n' >"$fixture/Cargo.lock"
manifest_before="$(shasum -a 256 "$fixture/Cargo.toml" | awk '{print $1}')"
lock_before="$(shasum -a 256 "$fixture/Cargo.lock" | awk '{print $1}')"
if run_stamp 0.1.0-rc.1 >"$fixture/rollback.out" 2>"$fixture/rollback.err"; then
  die "stamp succeeded when lockfile alignment failed"
fi
test "$(shasum -a 256 "$fixture/Cargo.toml" | awk '{print $1}')" = "$manifest_before" ||
  die "failed lockfile alignment did not restore Cargo.toml"
test "$(shasum -a 256 "$fixture/Cargo.lock" | awk '{print $1}')" = "$lock_before" ||
  die "failed lockfile alignment did not restore Cargo.lock"
mv "$fixture/Cargo.lock.valid" "$fixture/Cargo.lock"

# shellcheck disable=SC2016 # Verify shell-looking input remains inert.
for invalid in \
  '1.2' \
  'v1.2.3' \
  '1.2.3 beta.1' \
  '1.2.3-' \
  '1.2.3-beta' \
  '1.2.3-$(touch SHOULD_NOT_EXIST)'; do
  before="$(shasum -a 256 "$fixture/Cargo.toml" | awk '{print $1}')"
  if run_stamp "$invalid" >"$fixture/invalid.out" 2>"$fixture/invalid.err"; then
    die "invalid version was accepted: $invalid"
  fi
  after="$(shasum -a 256 "$fixture/Cargo.toml" | awk '{print $1}')"
  test "$before" = "$after" || die "invalid version modified Cargo.toml: $invalid"
done

test ! -e "$fixture/SHOULD_NOT_EXIST" ||
  die "invalid version executed shell content"

if run_stamp >"$fixture/missing.out" 2>"$fixture/missing.err"; then
  die "missing version argument was accepted"
fi

printf 'stamp version contract: ok\n'
