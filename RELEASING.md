# Releasing Pocket

This file is the canonical release checklist for Pocket.

## Release Targets

Every tagged release should account for these deliverables:

- Linux: CLI binary `pocket-linux-x86_64`
- macOS: Tauri `.app` bundle artifacts from `gui/src-tauri/target/release/bundle/macos/`
- macOS: Tauri `.dmg` bundle artifacts from `gui/src-tauri/target/release/bundle/dmg/`
- Windows: CLI binary `pocket-windows-x86_64.exe`
- Windows: NSIS installer artifacts from `gui/src-tauri/target/release/bundle/nsis/`
- Windows: MSI installer artifacts from `gui/src-tauri/target/release/bundle/msi/`

Current platform notes:

- macOS bundles can be notarized automatically when Apple credentials are configured.
- Windows artifacts are currently unsigned.
- Linux is currently treated as a CLI release target, not a first-class desktop bundle target.

## Feature-Completeness Gate

Before cutting a release, verify the release scope is accurate for the features that changed:

- Shared wallet behavior in `src/lib.rs` is implemented and covered by tests where the change is security-sensitive or protocol-sensitive.
- CLI behavior in `src/main.rs` is updated for any new wallet or transaction features.
- GUI behavior in `gui/src-tauri/src/main.rs` and `gui/dist/index.html` is updated when the feature is intended to be available in the desktop app.
- If a feature is CLI-only, call that out explicitly in the release notes instead of implying full desktop parity.

Known GUI parity note:

- Some advanced/operator-oriented flows may still remain CLI-first as new features land

Do not describe a release as full GUI parity unless any newly added CLI-only flows are called out explicitly.

## Pre-Release Checklist

- Bump versions where needed:
  - Root crate version in `Cargo.toml`
  - Tauri app version in `gui/src-tauri/tauri.conf.json`
- Update release-facing docs if packaging or artifact behavior changed:
  - `docs/release-pipeline.md`
  - `docs/packaging-macos.md`
  - `docs/packaging-windows.md`
- Keep GitHub Actions pinned to the repo's Tauri CLI major/minor version instead of installing `tauri-cli` unpinned.
- Review the current diff for accidental secrets, debug flags, or environment-specific paths.
- Confirm any new protocol, signing, or storage changes have regression tests.

## Verification Checklist

Run and pass:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

If the release affects the desktop app, also confirm:

- The Tauri backend still builds logically against the shared library API.
- The GUI uses the intended backend commands for the changed feature.
- Platform-specific packaging docs still match the workflow behavior.

If practical before a production tag, smoke-test:

- Linux CLI startup and one read-only wallet command
- macOS desktop launch
- Windows desktop launch

## GitHub Actions Release Flow

Tagged releases are published by `.github/workflows/release.yml`.

Current jobs:

- `build-linux-cli`
- `build-windows-cli`
- `build-macos`
- `build-windows`
- `release`

To publish a release:

```sh
git tag vX.Y.Z
git push origin vX.Y.Z
```

Or trigger the workflow manually through `workflow_dispatch`.

## Secrets And Signing

macOS notarization secrets:

- `APPLE_ID`
- `APPLE_TEAM_ID`
- `APPLE_PASSWORD`

Windows signing:

- Not implemented yet
- If Windows signing is added later, add it to the Windows release job rather than changing artifact names again

## Post-Release Checklist

- Confirm the GitHub release contains:
  - Linux CLI artifact
  - Windows CLI artifact
  - macOS `.app` artifact
  - macOS `.dmg` artifact
  - Windows NSIS installer
  - Windows MSI installer
- Download and sanity-check at least one artifact from each intended platform family.
- Verify release notes describe any platform limitations clearly, especially:
  - Windows unsigned status
  - Linux desktop absence, if still true
  - CLI-only features that are not present in the GUI
