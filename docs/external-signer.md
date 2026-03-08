# External Signer Hook

Pocket can delegate transaction signing to a hardware wallet, HSM, or wrapper script through a generic command hook.

## Configure
```bash
pocket set-external-signer \
  --command '/usr/local/bin/pocket-hsm-sign' \
  --address pc1... \
  --pubkey-hex <32-byte-ed25519-pubkey-hex>
```

The command receives canonical sign bytes as hex on stdin and in `POCKET_SIGN_BYTES_HEX`.
It must print the 64-byte ed25519 signature as hex to stdout.

## Use
```bash
pocket send-external --kind transfer --to pc1... --amount 10 --fee 1 --chain-id peace-mainnet --rpc https://rpc.example.com --token <bearer>
```

Pocket verifies that the configured public key derives to the configured address and verifies the returned signature before submission.
