# Agent Context

**This repo:** `ffreis-platform-configctl` — CLI for managing platform configuration
state in DynamoDB. Handles scoped configs and AES-256-GCM encrypted secrets with
Argon2id key derivation.

## Non-obvious facts

- **Secret values are read from stdin only.** Never pass secrets via CLI args — they
  would appear in shell history and process listings. Do not add argument-based secret
  inputs.

- **AAD (additional authenticated data) prevents ciphertext transplant attacks.**
  The encryption uses the composite key `PROJECT#{project}#ENV#{env}#KEY#{key}` as AAD.
  Changing the DynamoDB key format without updating AAD breaks decryption of all
  existing secrets.

- **DynamoDB schema:**
  - PK: `PROJECT#{project}#ENV#{env}`
  - SK: `CONFIG#{key}` for plain configs, `SECRET#{key}` for encrypted secrets

- **Exit codes:** 0 = success, 1 = error, 2 = key not found.

- **Secrets are always masked as `***` in logs and output.** Do not add code paths
  that print secret values even in debug mode.

- **Export/import ciphertext** — export stores encrypted blobs; diff shows `<encrypted>`
  for secret fields, never plaintext.

## Structure

```
cmd/              ← Cobra CLI boundary (no business logic)
internal/appconfig/
internal/store/   ← DynamoDB abstraction (Store interface)
internal/crypto/  ← AES-256-GCM encryption (Encryptor interface)
internal/backup/  ← export/import format and checksum
internal/diff/    ← live vs. snapshot comparison
internal/validate/← rule-based validation engine
internal/logger/  ← structured zap logging with secret masking
```

## Build/run

```bash
export CONFIGCTL_TABLE=platform-config CONFIGCTL_SECRET_KEY="passphrase"
platform-configctl config get database_url --project payments --env prod
platform-configctl secret set api_key --project payments --env prod  # reads from stdin
```

## Keeping this file current

- **If you discover a fact not reflected here:** add it before finishing your task.
- **If something here is wrong or outdated:** correct it in the same commit as the code change.
- **If you rename a file, command, or concept referenced here:** update the reference.
