# Pocket Release Pipeline

See [RELEASING.md](../RELEASING.md) for the full release checklist and platform completeness gates.

`release.yml` publishes:
- Linux CLI artifacts
- Windows CLI artifacts
- macOS `.app` bundles from `gui/src-tauri/target/release/bundle/macos/`
- macOS `.dmg` bundles from `gui/src-tauri/target/release/bundle/dmg/`
- Windows NSIS installers from `gui/src-tauri/target/release/bundle/nsis/`
- Windows MSI installers from `gui/src-tauri/target/release/bundle/msi/`
- optional notarized macOS `.dmg` when Apple credentials are present

Secrets used by notarization:
- `APPLE_ID`
- `APPLE_TEAM_ID`
- `APPLE_PASSWORD`

Notes:
- The workflow pins `tauri-cli` to `2.5.1` to match the repo's Tauri crates.
- Windows artifacts are currently published unsigned.
- The CI workflow also builds unsigned macOS and Windows Tauri bundles on pushes and PRs so packaging regressions show up before a tagged release.
