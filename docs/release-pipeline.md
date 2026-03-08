# Pocket Release Pipeline

`release.yml` publishes:
- Linux CLI artifacts
- macOS Tauri bundles
- optional notarized macOS `.dmg` when Apple credentials are present

Secrets used by notarization:
- `APPLE_ID`
- `APPLE_TEAM_ID`
- `APPLE_PASSWORD`
