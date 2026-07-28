#!/usr/bin/env bash
# Verify the downloaded release attachments are exactly the archive set the
# Release Prepare workflow publishes for this version — every expected archive
# present, nothing else alongside them.
#
# Provenance of the producing run is established beforehand by
# verify_prepare_run.sh; this script only decides what gets attached.

set -euo pipefail

usage='usage: verify_release_artifacts.sh <artifact-dir> <version>'

die() {
  printf 'release artifacts: %s\n' "$*" >&2
  exit 1
}

artifact_dir="${1:?$usage}"
version="${2:?$usage}"

test -d "$artifact_dir" || die "missing artifact directory: $artifact_dir"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z][A-Za-z0-9-]*\.[0-9]+)?$ ]] ||
  die "invalid release version: $version"

# Mirrors the build matrix in .github/workflows/release-prepare.yml. Adding a
# release target means changing both lists in the same commit.
expected=(
  "pagedb-fsck-${version}-linux-x64.tar.gz"
  "pagedb-fsck-${version}-linux-arm64.tar.gz"
  "pagedb-fsck-${version}-macos-arm64.tar.gz"
  "pagedb-fsck-${version}-macos-x64.tar.gz"
  "pagedb-fsck-${version}-windows-x64.zip"
)

# Both directions are checked by name. A count comparison would be shorter but
# would let one absence and one intruder cancel out, and it reports "wrong
# number of files" where the useful message is which file.
for archive in "${expected[@]}"; do
  path="$artifact_dir/$archive"
  # Symlinks are rejected ahead of the existence test so a dangling link is
  # reported as what it is rather than as an absent archive.
  if test -L "$path" || { test -e "$path" && test ! -f "$path"; }; then
    die "release archive is not a regular file: $archive"
  elif test ! -e "$path"; then
    die "missing release archive: $archive"
  fi
done

shopt -s nullglob dotglob
entries=("$artifact_dir"/*)
shopt -u nullglob dotglob

for entry in "${entries[@]}"; do
  name="${entry##*/}"
  known=""
  for archive in "${expected[@]}"; do
    if test "$name" = "$archive"; then
      known=1
      break
    fi
  done
  test -n "$known" || die "unexpected release attachment: $name"
done

printf 'release artifacts: ok\n'
