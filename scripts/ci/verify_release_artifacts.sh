#!/usr/bin/env bash
# Verify that a successful Release Prepare run produced the exact release set.

set -euo pipefail

die() {
  printf 'release artifacts: %s\n' "$*" >&2
  exit 1
}

run_json="${1:?usage: verify_release_artifacts.sh <run.json> <artifact-dir> <version> <commit>}"
artifact_dir="${2:?usage: verify_release_artifacts.sh <run.json> <artifact-dir> <version> <commit>}"
version="${3:?usage: verify_release_artifacts.sh <run.json> <artifact-dir> <version> <commit>}"
commit="${4:?usage: verify_release_artifacts.sh <run.json> <artifact-dir> <version> <commit>}"

test -f "$run_json" || die "missing workflow-run metadata: $run_json"
test -d "$artifact_dir" || die "missing artifact directory: $artifact_dir"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z][A-Za-z0-9-]*\.[0-9]+)?$ ]] ||
  die "invalid release version: $version"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "invalid release commit: $commit"

jq -e \
  --arg commit "$commit" \
  '.head_sha == $commit
   and .path == ".github/workflows/release-prepare.yml"
   and .event == "push"
   and .status == "completed"
   and .conclusion == "success"' \
  "$run_json" >/dev/null ||
  die "selected run is not a successful Release Prepare run for the tag commit"

expected=(
  "pagedb-fsck-${version}-linux-x64.tar.gz"
  "pagedb-fsck-${version}-linux-arm64.tar.gz"
  "pagedb-fsck-${version}-macos-arm64.tar.gz"
  "pagedb-fsck-${version}-macos-x64.tar.gz"
  "pagedb-fsck-${version}-windows-x64.zip"
)

shopt -s nullglob dotglob
entries=("$artifact_dir"/*)
shopt -u nullglob dotglob
test "${#entries[@]}" -eq "${#expected[@]}" ||
  die "expected exactly ${#expected[@]} release archives"

for entry in "${entries[@]}"; do
  test -f "$entry" && test ! -L "$entry" ||
    die "unexpected release artifact: $entry"
done
for archive in "${expected[@]}"; do
  test -f "$artifact_dir/$archive" ||
    die "missing release archive: $archive"
done

printf 'release artifacts: ok\n'
