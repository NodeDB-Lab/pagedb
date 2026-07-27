#!/usr/bin/env bash
# Verify that a prepared artifact set belongs to the requested release.

set -euo pipefail

die() {
  printf 'release provenance: %s\n' "$*" >&2
  exit 1
}

provenance="${1:?usage: verify_release_provenance.sh <provenance.json> <artifact-dir>}"
artifact_dir="${2:?usage: verify_release_provenance.sh <provenance.json> <artifact-dir>}"

: "${EXPECTED_COMMIT:?EXPECTED_COMMIT is required}"
: "${EXPECTED_REPOSITORY:?EXPECTED_REPOSITORY is required}"
: "${EXPECTED_RUN_ID:?EXPECTED_RUN_ID is required}"
: "${EXPECTED_TAG:?EXPECTED_TAG is required}"
: "${EXPECTED_VERSION:?EXPECTED_VERSION is required}"

test -f "$provenance" || die "missing provenance file: $provenance"
test -d "$artifact_dir" || die "missing artifact directory: $artifact_dir"
[[ "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z][A-Za-z0-9-]*\.[0-9]+)?$ ]] ||
  die "invalid expected version: $EXPECTED_VERSION"

jq -e -s \
  --arg commit "$EXPECTED_COMMIT" \
  --arg repository "$EXPECTED_REPOSITORY" \
  --arg run_id "$EXPECTED_RUN_ID" \
  --arg tag "$EXPECTED_TAG" \
  --arg version "$EXPECTED_VERSION" \
  'length == 1
   and .[0].schema == 1
   and .[0].repository == $repository
   and .[0].tag == $tag
   and .[0].version == $version
   and .[0].commit == $commit
   and .[0].prepare_run_id == $run_id' \
  "$provenance" >/dev/null ||
  die "prepared run provenance does not match the requested release"

expected_archives=(
  "pagedb-fsck-${EXPECTED_VERSION}-linux-x64.tar.gz"
  "pagedb-fsck-${EXPECTED_VERSION}-linux-arm64.tar.gz"
  "pagedb-fsck-${EXPECTED_VERSION}-macos-arm64.tar.gz"
  "pagedb-fsck-${EXPECTED_VERSION}-macos-x64.tar.gz"
  "pagedb-fsck-${EXPECTED_VERSION}-windows-x64.zip"
)

shopt -s nullglob dotglob
entries=("$artifact_dir"/*)
shopt -u nullglob dotglob
test "${#entries[@]}" -eq "${#expected_archives[@]}" ||
  die "expected exactly ${#expected_archives[@]} release archives"

for entry in "${entries[@]}"; do
  test -f "$entry" || die "unexpected non-file release attachment: $entry"
done
for archive in "${expected_archives[@]}"; do
  test -f "$artifact_dir/$archive" ||
    die "prepared run is missing $archive"
done

printf 'release provenance: ok\n'
