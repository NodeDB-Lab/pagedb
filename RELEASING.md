# Releasing PageDB

PageDB separates preparation from distribution so a crates.io or GitHub
Release retry cannot silently substitute another build:

1. `Release Prepare` runs from a pushed `v*` tag. It validates the tag, runs
   the complete reusable test suite, builds five `pagedb-fsck` archives, and
   records immutable provenance. It does not publish anything.
2. `Release` is dispatched manually with the tag and successful prepare run
   ID. It can publish the crate, create the GitHub Release, or retry either
   stage independently.

The prepare-run ID is not trusted by itself. Distribution requires its
provenance to match the repository, tag, package version, peeled tag commit,
and run ID, then requires the exact five expected archives.

## Before tagging

Start from the intended release commit on `main`, confirm its normal CI is
green, and update `CHANGELOG.md`. The base version in `Cargo.toml` must match
the tag's `X.Y.Z` component:

- `Cargo.toml` version `0.2.0` accepts `v0.2.0`;
- the same base accepts a prerelease such as `v0.2.0-beta.1`;
- other tag forms are rejected.

Run the local release contracts:

```bash
bash scripts/test-stamp-version.sh
bash scripts/test-release-provenance.sh
bash scripts/test-release-workflow-contract.sh
actionlint .github/workflows/release-prepare.yml \
  .github/workflows/release-validate.yml \
  .github/workflows/release.yml
cargo package --locked
```

These checks cover tag/stage wiring, exact artifact provenance, the macOS x64
cross-build runner, immutable action pins, safe idempotent version and lockfile
stamping, rollback after a failed stamp, and the absence of external-engine or
native-toolchain release prerequisites. `actionlint` parses the three release
workflows independently of those contract assertions. `cargo package
--locked` verifies the crate payload without publishing it.

The GitHub repository must already have:

- `CARGO_REGISTRY_TOKEN` configured for the `crates.io` environment;
- the intended environment approval rules;
- GitHub Actions permission to create releases.

Those are repository controls, not package dependencies. The release
workflows do not install RocksDB, SQLite, redb, Clang, libclang, or another
external benchmark engine.

## Prepare the release

Create and push the annotated tag through the normal reviewed Git procedure:

```bash
git tag -a v0.2.0 -m "pagedb v0.2.0"
git push origin v0.2.0
```

`Release Prepare` must complete:

- reusable tag validation;
- the full `.github/workflows/test.yml` suite;
- `pagedb-fsck` builds for Linux x64, Linux arm64, macOS arm64, macOS x64, and
  Windows x64;
- `release-provenance.json` upload;
- a summary containing the exact distribution command.

The macOS x64 binary cross-compiles on the current Apple Silicon
`macos-latest` runner. All prepare artifacts are retained for 14 days.

## Distribute the prepared run

Use the command emitted by `Release Prepare`, or dispatch it explicitly:

```bash
gh workflow run release.yml \
  -f tag=v0.2.0 \
  -f prepare_run_id=123456789
```

Before either publication stage starts, the workflow downloads the selected
prepare run and requires exact equality for:

- provenance schema;
- repository;
- tag;
- package version;
- peeled tag commit;
- prepare run ID.

It also requires exactly named archives for all five supported release labels.
A wrong run ID therefore fails closed instead of attaching plausible-looking
files from another build.

The crate stage aligns `Cargo.toml` and `Cargo.lock`, then performs a locked
verifying `cargo publish`. `--allow-dirty` permits the deliberate release
version edits; it does not disable Cargo's package verification build. An
already indexed crate version is a successful no-op.

## Retry one stage

Reuse the same tag and prepare run when only an external publication stage
failed:

```bash
# Retry only the GitHub Release.
gh workflow run release.yml \
  -f tag=v0.2.0 \
  -f prepare_run_id=123456789 \
  -f publish_crate=false

# Retry only crates.io publication.
gh workflow run release.yml \
  -f tag=v0.2.0 \
  -f prepare_run_id=123456789 \
  -f github_release=false
```

Create a new release commit and tag only when the source or packaged bytes must
change.

## Final verification

1. Confirm the crates.io version and checksum exist.
2. Confirm the GitHub Release points to the intended tag and has the correct
   prerelease state.
3. Confirm all five `pagedb-fsck` archives are attached.
4. Download and unpack at least one archive. Run `pagedb-fsck` without
   arguments and confirm it prints usage and exits with status 2.
5. Retain the prepare and distribution run URLs with the release record.

If distribution is intentionally abandoned, leave the tag and prepare
artifacts unchanged until the decision is reviewed.

Deleting or moving a published release tag is not a retry mechanism.
