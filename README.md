# Pocket

Pocket is the Peace wallet.

## Repo role

- This repository is the public release/downloads repo for Pocket.
- End users should come here for installers and release notes.
- Primary development happens in `../pocket_dev`.

## If you are Codex

- Do not expect the main wallet source tree here.
- Use `../pocket_dev` for wallet code, CLI work, Tauri GUI work, signing flows, and tests.
- Use this repo for public release messaging and download/distribution tasks.

## Related repos

- `../pocket_dev`: primary development repo for Pocket
- `../lantern`: public release repo for the Lantern full node
- `../lantern_dev`: primary development repo for the Lantern full node
- `../5310s.com`: website and browser miner that expects users to bring a Pocket address

## Pocket Downloads

This repository is now the public downloads and releases repo for Pocket.

Use the [Releases](https://github.com/5310S/Pocket/releases) page to download installers for:
- Linux
- macOS
- Windows

What changed
- The application source code and development work were moved to a separate internal repository.
- This repo is intentionally kept minimal so end users can access releases without browsing the source tree.

For users
- Download the installer for your operating system from the Releases page.
- Each release includes installation instructions in the release notes.
