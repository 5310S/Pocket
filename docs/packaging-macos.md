# Pocket macOS packaging (draft)

Prereqs
- macOS with Xcode command-line tools.
- Rust toolchain + `tauri-cli` 2.5.1 (`cargo install tauri-cli --version 2.5.1 --locked`).
- Apple Developer ID certs if you want signed/notarized output (optional for dev builds).

Build unsigned dev bundle
```sh
cd gui
cargo tauri build --ci --verbose
```
Artifacts land in:
- `gui/src-tauri/target/release/bundle/macos/*.app`
- `gui/src-tauri/target/release/bundle/dmg/*.dmg`

Signing/notarization outline
1) Set env:
   - `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_PASSWORD` (app-specific password) or use keychain.
2) Provide certificate:
   - Import "Developer ID Application" cert into login keychain, or set `TAURI_PRIVATE_KEY`/`TAURI_CERTIFICATE`.
3) Build & sign:
   - `cargo tauri build --ci --verbose --target universal-apple-darwin`
4) Notarize (manual):
   - `xcrun notarytool submit path/to/pocket-gui.dmg --apple-id $APPLE_ID --team-id $APPLE_TEAM_ID --password $APPLE_PASSWORD --wait`
5) Staple:
   - `xcrun stapler staple path/to/pocket-gui.dmg`

Release pipeline
- GitHub Actions workflow `release.yml` publishes release artifacts on tags.
- GitHub Actions workflow `ci.yml` continues to build/test on pushes and PRs.
- If you set secrets `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_PASSWORD`, the macOS release workflow notarizes/staples the `.dmg` automatically. Otherwise it remains unsigned for manual testing.
- Add an app icon at `gui/src-tauri/icons/icon.png` (512x512) to brand the bundle; currently a minimal placeholder is included.
