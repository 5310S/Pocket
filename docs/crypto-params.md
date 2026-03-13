# Pocket Crypto Parameters

Pocket stores the mnemonic in `~/.pocket/keystore.json` using:

- `Argon2id` from `argon2` crate `0.5.3`
- Default Argon2 params from that crate version
- Memory cost: `19 * 1024 KiB` (`19456 KiB`)
- Time cost: `2`
- Parallelism: `1`
- Output length: `32` bytes
- Cipher: `AES-256-GCM`
- Salt length: `16` random bytes
- Nonce length: `12` random bytes

Notes:

- These parameters are implicit today because Pocket uses `Argon2::default()` in [src/lib.rs](/Users/zip/projects/peace/pocket/src/lib.rs:451).
- Existing keystores depend on those parameters. Changing them without storing per-keystore KDF metadata would break decryption.
- The local profile API for Weave/local tooling exposes `/payout` without the attestation token, and `/profile` only when a configured bearer token matches.
- Pocket now refuses non-loopback profile binds unless a profile bearer token is configured.
