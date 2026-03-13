# Pocket Windows packaging

Prereqs
- Windows with the Rust toolchain installed.
- WebView2-capable build environment (GitHub `windows-latest` works for CI).
- `tauri-cli` 2.5.1 (`cargo install tauri-cli --version 2.5.1 --locked`) for GUI builds.

Build unsigned CLI
```powershell
cargo build --release
```

CLI output:
- `target\release\pocket.exe`

Build unsigned GUI bundle
```powershell
cd gui
cargo tauri build --ci --verbose
```

GUI artifacts land under:
- `gui\src-tauri\target\release\bundle\nsis\Pocket_*_x64-setup.exe`
- `gui\src-tauri\target\release\bundle\msi\Pocket_*_x64_en-US.msi`

Release pipeline
- GitHub Actions workflow `release.yml` publishes:
  - `pocket-windows-x86_64.exe` for the CLI
  - Windows NSIS installers from `gui/src-tauri/target/release/bundle/nsis/`
  - Windows MSI installers from `gui/src-tauri/target/release/bundle/msi/`
- GitHub Actions workflow `ci.yml` also builds the unsigned Windows Tauri bundle on pushes and PRs.

Signing
- Windows bundles are currently published unsigned.
- If you want first-class signed installers later, add a certificate-backed signing step to the Windows release job rather than changing the artifact layout again.
