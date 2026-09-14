# Agent Context

**This repo:** `ffreis-platform-configctl` — CLI for managing platform configuration
state in DynamoDB. Handles scoped configs and AES-256-GCM encrypted secrets with
Argon2id key derivation.

**Two binaries, one module.** `cmd/platform-configctl` is the config/secret
control-plane CLI described throughout this file. `cmd/vaultctl` is a
separate, independent binary that owns the fleet's credential-vault surface
(get/put/exec/export-env/list/delete/backup against the identity/repo/root
DynamoDB tables) — its own identity, own env vars, own profiles file, on
purpose (see "vaultctl" below). Both import `internal/store`,
`internal/crypto`, `internal/logger`, and `internal/profile` directly via
Go's `internal/` visibility rule; neither imports the other's `cmd` package.

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
  gates `--reveal`'s print path. This is the fingerprint/reveal-guard half of what was
  originally one PR that also added `secret exec`/`secret export-env` directly to this
  binary — those two moved to the separate `vaultctl` binary (see below) because they
  are vault-specific leak-control primitives, not configctl's job; the fingerprint and
  `CONFIGCTL_NO_REVEAL` stayed here because they harden `secret get` for ANY secret,
  not just vault ones.

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
  command already makes inside `RunE`, after `PreRunE` has run. `internal/profile`'s
  `DefaultPath` takes the app name as a parameter (`DefaultPath("configctl")`) — it is
  shared with `vaultctl`, which calls `DefaultPath("vaultctl")` for its own, separate
  profiles file.

## vaultctl

`cmd/vaultctl` is a second, independent binary in this module — see "Two binaries,
one module" above. Command surface: `get/put/exec/export-env/list/delete` all take
`<tier> <key>` (or just `<tier>` for `list`) plus a required `--env`; `backup export`
takes `--tier`/`--env`/`--output`; `backup import` takes only `--input` (see below).

- **No `--table`, no `--project`, no default `--env`.** `<tier>` (`identity`, `repo`,
  or `root`) plus `--env` (`dev` or `prod`, no default — see `internal/vaulttier`)
  resolve the physical table (`ffreis-vault-<tier>-<env>`) internally; the operator
  never names a table. `project` is hardcoded to the literal `"vault"` in every
  item's PK — this vault has no per-project dimension. `--env` is deliberately never
  defaultable, not even via `--profile`: an omitted flag must never silently resolve
  to prod.

- **AAD binds tier, not just project+env+key.** All vault items share the same
  `project` (`"vault"`), so `internal/vaulttier.AADKey(tier, key)` folds tier into the
  AAD key-name component (`tier + "/" + key`) before it reaches
  `crypto.NewAESGCMEncryptor`. Without this, a same-named secret in two different
  tiers would derive IDENTICAL AAD despite living in physically different DynamoDB
  tables — ciphertext copied from one tier's table into another's under the same key
  name would decrypt successfully, exactly the transplant attack AAD exists to
  prevent. Never construct an `AESGCMEncryptor` for a vault item without routing the
  key name through `AADKey` first.

- **`VAULTCTL_SECRET_KEY` / `VAULTCTL_NO_REVEAL`** are vaultctl's own env vars —
  deliberately not `CONFIGCTL_SECRET_KEY`/`CONFIGCTL_NO_REVEAL`. The two binaries
  share internals but are independent tools; a shell that happens to have configctl's
  variables set must never silently satisfy vaultctl's too.

- **`put` refuses an empty, whitespace-only, or bare `"-"` value.** Both are
  real-incident classes (a write that "succeeds" while storing garbage, undetected,
  because presence checks pass on an empty or placeholder string) — see
  `internal/guard.ValidateSecretValue`, shared with platform-configctl's own
  `secret set`.

- **`backup import` takes no `--tier`/`--env`**, matching platform-configctl's own
  `backup import` (which also takes no `--project`/`--env`). The file self-describes
  its origin table via `Metadata.Tier` (set by `backup export`, an optional field on
  `internal/backup.Metadata` that platform-configctl's own exports leave empty) —
  import resolves the same table from the file's own metadata rather than trusting a
  repeated or possibly-mismatched operator-supplied flag.

## Structure

```
cmd/                  ← platform-configctl's Cobra CLI boundary (no business logic)
cmd/vaultctl/          ← vaultctl: its own main + full command tree, package main
internal/appconfig/
internal/store/       ← DynamoDB abstraction (Store interface)
internal/crypto/      ← AES-256-GCM encryption (Encryptor interface)
internal/backup/      ← export/import format and checksum (shared by both binaries)
internal/diff/        ← live vs. snapshot comparison
internal/validate/    ← rule-based validation engine
internal/logger/      ← structured zap logging with secret masking
internal/profile/     ← named --profile default resolution, per-app path (shared)
internal/guard/       ← leak-control primitives shared by both binaries: fingerprint,
                         env-truthy kill-switch parsing, empty/"-" value guard
internal/vaulttier/   ← vaultctl's tier validation, table resolution, tier-bound AAD
```

## Build/run

```bash
export CONFIGCTL_TABLE=platform-config CONFIGCTL_SECRET_KEY="passphrase"
platform-configctl config get database_url --project payments --env prod
platform-configctl secret set api_key --project payments --env prod  # reads from stdin

export VAULTCTL_SECRET_KEY="passphrase"
echo -n "s3cr3t" | vaultctl put identity github-pat --env prod
vaultctl get identity github-pat --env prod  # masked + fingerprint; --reveal to decrypt
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
