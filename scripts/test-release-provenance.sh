#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'release provenance contract: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="$repo_root/scripts/ci/verify_release_provenance.sh"
test -f "$verifier" || die "missing scripts/ci/verify_release_provenance.sh"

fixture="$(mktemp -d "${TMPDIR:-/tmp}/pagedb-release-provenance.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/artifacts" "$fixture/provenance"

export EXPECTED_COMMIT=0123456789abcdef0123456789abcdef01234567
export EXPECTED_REPOSITORY=nodedb-lab/pagedb
export EXPECTED_RUN_ID=123456789
export EXPECTED_TAG=v0.2.0-beta.1
export EXPECTED_VERSION=0.2.0-beta.1

provenance="$fixture/provenance/release-provenance.json"
jq -n \
  --arg commit "$EXPECTED_COMMIT" \
  --arg repository "$EXPECTED_REPOSITORY" \
  --arg run_id "$EXPECTED_RUN_ID" \
  --arg tag "$EXPECTED_TAG" \
  --arg version "$EXPECTED_VERSION" \
  '{schema:1, repository:$repository, tag:$tag, version:$version, commit:$commit, prepare_run_id:$run_id}' \
  >"$provenance"

for archive in \
  "pagedb-fsck-${EXPECTED_VERSION}-linux-x64.tar.gz" \
  "pagedb-fsck-${EXPECTED_VERSION}-linux-arm64.tar.gz" \
  "pagedb-fsck-${EXPECTED_VERSION}-macos-arm64.tar.gz" \
  "pagedb-fsck-${EXPECTED_VERSION}-macos-x64.tar.gz" \
  "pagedb-fsck-${EXPECTED_VERSION}-windows-x64.zip"; do
  : >"$fixture/artifacts/$archive"
done

verify() {
  bash "$verifier" "$provenance" "$fixture/artifacts"
}

verify | grep -F 'release provenance: ok' >/dev/null ||
  die "valid provenance and artifact set was rejected"

for field in repository tag version commit prepare_run_id; do
  original="$fixture/original.json"
  cp "$provenance" "$original"
  jq --arg field "$field" '.[$field] = "wrong"' "$original" >"$provenance"
  if verify >"$fixture/invalid.out" 2>"$fixture/invalid.err"; then
    die "mismatched $field was accepted"
  fi
  mv "$original" "$provenance"
done

cp "$provenance" "$fixture/original.json"
jq '.schema = 2' "$fixture/original.json" >"$provenance"
if verify >"$fixture/invalid.out" 2>"$fixture/invalid.err"; then
  die "unsupported provenance schema was accepted"
fi
mv "$fixture/original.json" "$provenance"

missing="$fixture/artifacts/pagedb-fsck-${EXPECTED_VERSION}-macos-x64.tar.gz"
mv "$missing" "$fixture/missing.archive"
if verify >"$fixture/missing.out" 2>"$fixture/missing.err"; then
  die "missing platform archive was accepted"
fi
mv "$fixture/missing.archive" "$missing"

: >"$fixture/artifacts/unexpected.txt"
if verify >"$fixture/extra.out" 2>"$fixture/extra.err"; then
  die "unexpected release attachment was accepted"
fi

printf 'release provenance contract: ok\n'
