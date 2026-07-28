#!/usr/bin/env bash
# Regression tests for the release verifiers.
#
# Generated data only — no network, no tracked fixtures, no assertions about
# workflow YAML layout. Every negative case asserts the reason for the
# rejection, so a verifier that breaks in an unrelated way (bad arity, missing
# jq, a typo in a guard) cannot pass by merely exiting nonzero.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
verify_run="$repo_root/scripts/ci/verify_prepare_run.sh"
verify_artifacts="$repo_root/scripts/ci/verify_release_artifacts.sh"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

version="0.2.0-beta.1"
commit="0123456789abcdef0123456789abcdef01234567"
other_commit="ffffffffffffffffffffffffffffffffffffffff"
artifacts="$work_dir/artifacts"
log="$work_dir/verifier.log"
failures=0

report_log() {
  sed 's/^/       /' "$log" >&2
}

expect_ok() {
  local label="$1"
  shift
  if "$@" >"$log" 2>&1; then
    printf 'ok   %s\n' "$label"
  else
    printf 'FAIL %s: expected success\n' "$label" >&2
    report_log
    failures=$((failures + 1))
  fi
}

expect_failure() {
  local label="$1" want="$2"
  shift 2
  if "$@" >"$log" 2>&1; then
    printf 'FAIL %s: expected failure, got success\n' "$label" >&2
    failures=$((failures + 1))
  elif grep -qF -- "$want" "$log"; then
    printf 'ok   %s\n' "$label"
  else
    printf 'FAIL %s: expected message containing: %s\n' "$label" "$want" >&2
    report_log
    failures=$((failures + 1))
  fi
}

# A successful prepare run for $commit, optionally mutated by a jq filter.
write_run() {
  local out="$1" filter="${2:-.}"
  jq -n --arg head_sha "$commit" \
    '{head_sha: $head_sha,
      path: ".github/workflows/release-prepare.yml",
      event: "push",
      status: "completed",
      conclusion: "success"}' |
    jq "$filter" >"$out"
}

seed_artifacts() {
  rm -rf "$artifacts"
  mkdir -p "$artifacts"
  local label
  for label in linux-x64 linux-arm64 macos-arm64 macos-x64; do
    : >"$artifacts/pagedb-fsck-${version}-${label}.tar.gz"
  done
  : >"$artifacts/pagedb-fsck-${version}-windows-x64.zip"
}

# ── prepare-run provenance ──────────────────────────────────────────────────

run_json="$work_dir/run.json"
write_run "$run_json"

expect_ok "prepare run: successful tag build" \
  bash "$verify_run" "$run_json" "$commit"

expect_failure "prepare run: different tag commit" "run head_sha is" \
  bash "$verify_run" "$run_json" "$other_commit"

write_run "$work_dir/failed.json" '.conclusion = "failure"'
expect_failure "prepare run: unsuccessful conclusion" "run conclusion is 'failure'" \
  bash "$verify_run" "$work_dir/failed.json" "$commit"

write_run "$work_dir/in-progress.json" '.status = "in_progress" | .conclusion = null'
expect_failure "prepare run: still running" "run status is 'in_progress'" \
  bash "$verify_run" "$work_dir/in-progress.json" "$commit"

write_run "$work_dir/other-workflow.json" '.path = ".github/workflows/test.yml"'
expect_failure "prepare run: different workflow" "run path is" \
  bash "$verify_run" "$work_dir/other-workflow.json" "$commit"

write_run "$work_dir/dispatched.json" '.event = "workflow_dispatch"'
expect_failure "prepare run: not a tag push" "run event is 'workflow_dispatch'" \
  bash "$verify_run" "$work_dir/dispatched.json" "$commit"

write_run "$work_dir/truncated.json" 'del(.conclusion)'
expect_failure "prepare run: absent field" "run conclusion is '<absent>'" \
  bash "$verify_run" "$work_dir/truncated.json" "$commit"

printf 'not json' >"$work_dir/garbage.json"
expect_failure "prepare run: malformed metadata" "not valid JSON" \
  bash "$verify_run" "$work_dir/garbage.json" "$commit"

expect_failure "prepare run: absent metadata file" "missing workflow-run metadata" \
  bash "$verify_run" "$work_dir/nonexistent.json" "$commit"

expect_failure "prepare run: malformed commit" "invalid release commit" \
  bash "$verify_run" "$run_json" "HEAD"

# ── release attachment set ──────────────────────────────────────────────────

seed_artifacts
expect_ok "artifacts: exact release set" \
  bash "$verify_artifacts" "$artifacts" "$version"

seed_artifacts
: >"$artifacts/unexpected.txt"
expect_failure "artifacts: extra attachment" "unexpected release attachment: unexpected.txt" \
  bash "$verify_artifacts" "$artifacts" "$version"

seed_artifacts
: >"$artifacts/.hidden"
expect_failure "artifacts: hidden attachment" "unexpected release attachment: .hidden" \
  bash "$verify_artifacts" "$artifacts" "$version"

# Renamed rather than deleted: the attachment count stays at five, so this
# reaches the by-name check instead of tripping a coarser cardinality guard.
seed_artifacts
mv "$artifacts/pagedb-fsck-${version}-windows-x64.zip" "$artifacts/pagedb-fsck-${version}-windows-x86.zip"
expect_failure "artifacts: missing archive at full count" \
  "missing release archive: pagedb-fsck-${version}-windows-x64.zip" \
  bash "$verify_artifacts" "$artifacts" "$version"

seed_artifacts
rm "$artifacts/pagedb-fsck-${version}-macos-x64.tar.gz"
expect_failure "artifacts: absent archive" \
  "missing release archive: pagedb-fsck-${version}-macos-x64.tar.gz" \
  bash "$verify_artifacts" "$artifacts" "$version"

seed_artifacts
rm "$artifacts/pagedb-fsck-${version}-linux-x64.tar.gz"
ln -s /etc/hostname "$artifacts/pagedb-fsck-${version}-linux-x64.tar.gz"
expect_failure "artifacts: symlinked archive" "is not a regular file" \
  bash "$verify_artifacts" "$artifacts" "$version"

seed_artifacts
rm "$artifacts/pagedb-fsck-${version}-linux-arm64.tar.gz"
mkdir "$artifacts/pagedb-fsck-${version}-linux-arm64.tar.gz"
expect_failure "artifacts: directory in place of archive" "is not a regular file" \
  bash "$verify_artifacts" "$artifacts" "$version"

seed_artifacts
expect_failure "artifacts: version mismatch" "missing release archive" \
  bash "$verify_artifacts" "$artifacts" "9.9.9"

expect_failure "artifacts: malformed version" "invalid release version" \
  bash "$verify_artifacts" "$artifacts" "not-a-version"

expect_failure "artifacts: absent directory" "missing artifact directory" \
  bash "$verify_artifacts" "$work_dir/nonexistent" "$version"

# ────────────────────────────────────────────────────────────────────────────

if test "$failures" -ne 0; then
  printf 'release artifact verification: %d test(s) failed\n' "$failures" >&2
  exit 1
fi

printf 'release artifact verification: tests passed\n'
