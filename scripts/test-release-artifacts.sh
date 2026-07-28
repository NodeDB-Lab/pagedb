#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="$repo_root/scripts/ci/verify_release_artifacts.sh"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

version="0.2.0-beta.1"
commit="0123456789abcdef0123456789abcdef01234567"
run_json="$work_dir/run.json"
artifacts="$work_dir/artifacts"

expect_failure() {
  local label="$1" metadata="$2" expected_commit="$3"
  shift
  shift 2
  if bash "$verifier" "$metadata" "$artifacts" "$version" "$expected_commit" \
    >"$work_dir/failure.log" 2>&1; then
    printf 'expected failure: %s\n' "$label" >&2
    exit 1
  fi
}

jq -n --arg head_sha "$commit" \
  '{head_sha:$head_sha, path:".github/workflows/release-prepare.yml",
    event:"push", status:"completed", conclusion:"success"}' >"$run_json"
mkdir "$artifacts"
touch \
  "$artifacts/pagedb-fsck-${version}-linux-x64.tar.gz" \
  "$artifacts/pagedb-fsck-${version}-linux-arm64.tar.gz" \
  "$artifacts/pagedb-fsck-${version}-macos-arm64.tar.gz" \
  "$artifacts/pagedb-fsck-${version}-macos-x64.tar.gz" \
  "$artifacts/pagedb-fsck-${version}-windows-x64.zip"

bash "$verifier" "$run_json" "$artifacts" "$version" "$commit"

expect_failure "different tag commit" "$run_json" \
  "ffffffffffffffffffffffffffffffffffffffff"

jq '.conclusion = "failure"' "$run_json" >"$work_dir/failed-run.json"
expect_failure "failed prepare run" "$work_dir/failed-run.json" "$commit"

touch "$artifacts/unexpected.txt"
expect_failure "extra artifact" "$run_json" "$commit"

rm "$artifacts/unexpected.txt" "$artifacts/pagedb-fsck-${version}-windows-x64.zip"
expect_failure "missing archive" "$run_json" "$commit"

printf 'release artifact verification: tests passed\n'
