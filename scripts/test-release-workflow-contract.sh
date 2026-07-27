#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'release workflow contract: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow_dir="$repo_root/.github/workflows"
prepare="$workflow_dir/release-prepare.yml"
validate="$workflow_dir/release-validate.yml"
release="$workflow_dir/release.yml"
test_workflow="$workflow_dir/test.yml"

for path in "$prepare" "$validate" "$release" "$test_workflow"; do
  test -f "$path" || die "missing ${path#"$repo_root"/}"
done

grep -F 'name: Release Prepare' "$prepare" >/dev/null ||
  die "prepare workflow has the wrong name"
grep -F 'tags:' "$prepare" >/dev/null ||
  die "prepare workflow is not tag-triggered"

(
  cd "$repo_root"
  cargo package -p pagedb --locked --allow-dirty --no-verify >/dev/null
) || die "tracked Cargo.lock cannot package the release crate"

grep -F 'uses: ./.github/workflows/release-validate.yml' "$prepare" >/dev/null ||
  die "prepare workflow bypasses reusable tag validation"
grep -F 'uses: ./.github/workflows/test.yml' "$prepare" >/dev/null ||
  die "prepare workflow bypasses the full reusable test suite"
grep -F 'name: release-provenance' "$prepare" >/dev/null ||
  die "prepare workflow does not retain release provenance"
grep -F 'retention-days: 14' "$prepare" >/dev/null ||
  die "prepare artifacts do not retain the documented retry window"
grep -F 'cargo build --locked --release --bin pagedb-fsck' "$prepare" >/dev/null ||
  die "prepared binaries are not built from the aligned lockfile"

grep -F 'workflow_call:' "$validate" >/dev/null ||
  die "tag validation is not reusable"
# shellcheck disable=SC2016 # Match the workflow expression literally.
grep -F 'ref: ${{ inputs.ref }}' "$validate" >/dev/null ||
  die "tag validation does not check out the requested ref"
grep -F 'commit:' "$validate" >/dev/null ||
  die "tag validation does not publish the exact tag commit"
# shellcheck disable=SC2016 # Match the shell expression literally.
grep -F 'git rev-parse "refs/tags/${TAG}^{commit}"' "$validate" >/dev/null ||
  die "tag validation does not resolve the tag's peeled commit"

grep -F 'workflow_dispatch:' "$release" >/dev/null ||
  die "distribution workflow is not manually dispatched"
if grep -F 'tags:' "$release" >/dev/null; then
  die "distribution workflow still publishes directly from a tag push"
fi
grep -F 'prepare_run_id:' "$release" >/dev/null ||
  die "distribution workflow does not require a prepare run"
grep -F 'validate-prepare:' "$release" >/dev/null ||
  die "distribution workflow has no shared prepare-run gate"
test "$(
  grep -F -c 'needs: [validate-version, validate-prepare]' "$release"
)" -eq 2 ||
  die "crate and GitHub Release stages do not both depend on the prepare-run gate"
grep -F 'Verify prepared release provenance' "$release" >/dev/null ||
  die "distribution workflow does not verify prepared provenance"
grep -F 'run: bash scripts/ci/verify_release_provenance.sh' "$release" >/dev/null ||
  die "distribution workflow does not use the tested provenance verifier"
grep -F 'cargo publish -p pagedb --locked --allow-dirty' "$release" >/dev/null ||
  die "crate publication is not a locked verifying publish"

for contract in \
  scripts/test-stamp-version.sh \
  scripts/test-release-provenance.sh \
  scripts/test-release-workflow-contract.sh; do
  grep -F "bash $contract" "$test_workflow" >/dev/null ||
    die "$contract is not run by the reusable test workflow"
done

macos_x64_entry="$(
  awk '
    /target: x86_64-apple-darwin/ {
      print previous
      print
      getline
      print
      exit
    }
    { previous = $0 }
  ' "$prepare"
)"
grep -F 'runs-on: macos-latest' <<<"$macos_x64_entry" >/dev/null ||
  die "macOS x64 is not cross-built on the current Apple Silicon runner"
if grep -F 'macos-13' "$prepare" >/dev/null; then
  die "prepare workflow still selects the retired Intel runner"
fi

checkout_sha=3d3c42e5aac5ba805825da76410c181273ba90b1
upload_sha=043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
download_sha=3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
release_sha=3d0d9888cb7fd7b750713d6e236d1fcb99157228
rust_toolchain_sha=4cda84d5c5c54efe2404f9d843567869ab1699d4
rust_cache_sha=e18b497796c12c097a38f9edb9d0641fb99eee32
install_action_sha=41049aa56687c35e0afa74eed4f09cec4f9afabf

if grep -E \
  'uses: (actions/(checkout|upload-artifact|download-artifact)|softprops/action-gh-release|dtolnay/rust-toolchain)@(v[0-9]+|stable)' \
  "$prepare" "$validate" "$release" "$test_workflow" >/dev/null; then
  die "a release action still uses a mutable tag"
fi

while IFS= read -r use_line; do
  action_ref="${use_line#*uses: }"
  action_ref="${action_ref%% *}"
  [[ "$action_ref" == ./* ]] && continue
  [[ "$action_ref" =~ @[0-9a-f]{40}$ ]] ||
    die "release action is not immutably pinned: $action_ref"
done < <(
  grep -h -E '^[[:space:]]*(- )?uses:' \
    "$prepare" "$validate" "$release" "$test_workflow"
)

grep -R -F "uses: actions/checkout@$checkout_sha # v7" \
  "$prepare" "$validate" "$release" "$test_workflow" >/dev/null ||
  die "checkout v7 immutable pin is missing"
grep -F "uses: actions/upload-artifact@$upload_sha # v7" \
  "$prepare" "$test_workflow" >/dev/null ||
  die "upload-artifact v7 immutable pin is missing"
grep -F "uses: actions/download-artifact@$download_sha # v8" "$release" >/dev/null ||
  die "download-artifact v8 immutable pin is missing"
grep -F "uses: softprops/action-gh-release@$release_sha # v3" "$release" >/dev/null ||
  die "action-gh-release v3 immutable pin is missing"
grep -R -F "uses: dtolnay/rust-toolchain@$rust_toolchain_sha # stable" \
  "$prepare" "$validate" "$release" "$test_workflow" >/dev/null ||
  die "Rust toolchain action immutable pin is missing"
grep -F "uses: Swatinem/rust-cache@$rust_cache_sha # v2" "$test_workflow" >/dev/null ||
  die "Rust cache action immutable pin is missing"
grep -F "uses: taiki-e/install-action@$install_action_sha # v2.85.2" \
  "$test_workflow" >/dev/null ||
  die "tool installer action immutable pin is missing"

checkout_count="$(
  awk -v needle="uses: actions/checkout@$checkout_sha # v7" '
    index($0, needle) { count++ }
    END { print count + 0 }
  ' "$prepare" "$validate" "$release" "$test_workflow"
)"
credential_guard_count="$(
  awk '
    index($0, "persist-credentials: false") { count++ }
    END { print count + 0 }
  ' "$prepare" "$validate" "$release" "$test_workflow"
)"
test "$checkout_count" -eq "$credential_guard_count" ||
  die "every release checkout must disable persisted credentials"

if grep -F 'Swatinem/rust-cache' "$prepare" >/dev/null; then
  die "release artifact builds must not depend on a mutable compiler cache"
fi

if grep -E -i 'rocksdb|sqlite|redb|libclang|install llvm|install clang' \
  "$prepare" "$validate" "$release" >/dev/null; then
  die "release workflows add an external-engine or native-toolchain prerequisite"
fi

printf 'release workflow contract: ok\n'
