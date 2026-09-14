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

- **`CONFIGCTL_NO_REVEAL` kill switch.** Set to a truthy value (`1`/`true`/`yes`/`on`)
  and `secret get --reveal` refuses to decrypt/print the plaintext, regardless of the
  flag — this exists so a secret value can never be printed to a stream that lands in
  an AI agent's session transcript (a real PAT leaked this way on 2026-05-29). It only
  gates `--reveal`'s print path: `secret exec` and `secret export-env` are unaffected
  because neither of them ever writes plaintext to a stream configctl controls.

- **`secret exec <key> --as NAME -- <cmd> [args...]`** decrypts in-process and injects
  the plaintext into the child's environment as `NAME` (`cmd.Env = append(os.Environ(),
  NAME+"="+plaintext)`) — nothing touches configctl's own stdout/stderr, a file, or a
  log line. `--as` has no default (never silently uppercase the key) and is required.

- **`secret export-env <key> --as NAME --out <path>`** writes a single shell-quoted
  `export NAME=value` line to `--out` (required, no default — never stdout or an
  implicit path), mode 0600. configctl prints only a confirmation of the path, never
  the value. The caller is responsible for shredding the file.

- **`secret get` always computes a fingerprint** — `sha256(plaintext)[0:8]` hex — and
  includes it in both text and `--output json`, independent of `--reveal` and of
  `CONFIGCTL_NO_REVEAL`. This means `secret get` now always decrypts internally (it
  needs `CONFIGCTL_SECRET_KEY` to match), even when `--reveal` is not passed — a
  behaviour change from the earlier lazy-decrypt-only-on-reveal implementation.

- **`--profile <name>`** resolves default `table`/`project`/`env`/`region` from
  `~/.config/configctl/profiles.yaml`. An explicit `--table`/`--project`/`--env`/
  `--region` flag always wins over the profile; the profile only fills a value the
  environment (e.g. `CONFIGCTL_TABLE`) left empty. `addProjectEnvFlags` no longer
  calls `cmd.MarkFlagRequired` for `--project`/`--env` (cobra validates required flags
  *before* a leaf command's own `PreRunE` gets a chance to apply the profile fallback)
  — presence is instead enforced by the existing `requireProjectEnv` call every
  command already makes inside `RunE`, after `PreRunE` has run.

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
internal/profile/ ← named --profile default resolution (~/.config/configctl/profiles.yaml)
```

## Build/run

```bash
export CONFIGCTL_TABLE=platform-config CONFIGCTL_SECRET_KEY="passphrase"
platform-configctl config get database_url --project payments --env prod
platform-configctl secret set api_key --project payments --env prod  # reads from stdin
```

## Public repo — private-repo hygiene

This is a **public** GitHub repository. When writing commit messages, PR titles,
PR descriptions, or any other user-visible text, **never name private repos** —
website content, inventory, infra, Lambda, or data repos that are not publicly
listed. Use generic terms instead: "the fleet inventory", "a private consumer",
"internal infra", "private data repo", etc.

## Keeping this file current

- **If you discover a fact not reflected here:** add it before finishing your task.
- **If something here is wrong or outdated:** correct it in the same commit as the code change.
- **If you rename a file, command, or concept referenced here:** update the reference.
