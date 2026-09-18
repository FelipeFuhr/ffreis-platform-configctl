# Agent Context

**This repo:** `ffreis-platform-configctl` — CLI for managing platform configuration
state in DynamoDB. Handles scoped configs and AES-256-GCM encrypted secrets with
Argon2id key derivation.

**One binary, plus a shared library other repos import.** `cmd/platform-configctl`
is the only binary this repo builds — the config/secret control-plane CLI
described throughout this file. The fleet's credential-vault CLI, `vaultctl`,
used to live here as a second binary (`cmd/vaultctl`); it was split into its
own repo, `ffreis-platform-vaultctl`, which imports this module as a real Go
dependency to reuse this repo's storage, crypto, logging, profile, and
leak-guard code rather than duplicating it. That reuse is why
`pkg/crypto`, `pkg/store`, `pkg/guard`, `pkg/profile`, `pkg/backup`, and
`pkg/logger` live under `pkg/` (importable by any module) instead of
`internal/` (importable only from within this module) — see "Structure"
below. `internal/appconfig`, `internal/diff`, and `internal/validate` have no
consumer outside this binary, so they stayed `internal/`.

**Module path.** This module is `github.com/FelipeFuhr/ffreis-platform-configctl`
— it must match the repo's actual GitHub location (`FelipeFuhr/`, not
`ffreis/`) because an external module (`ffreis-platform-vaultctl`) now
resolves it by import path. It was briefly `github.com/ffreis/platform-configctl`
(a placeholder that happened to work only because nothing outside this repo
imported it); never revert to that — it breaks `go get` for every external
importer.

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
  binary — those two moved to `vaultctl` (now its own repo, see above) because they
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
  command already makes inside `RunE`, after `PreRunE` has run. `pkg/profile`'s
  `DefaultPath` takes the app name as a parameter (`DefaultPath("configctl")`) — the
  same function is used by `vaultctl` (`DefaultPath("vaultctl")`, in its own repo)
  for its own, separate profiles file.

- **vaultctl's tier logic is not here.** Table-name resolution per tier
  (`identity`/`repo`/`root`), the `--env`-never-defaults rule, and the tier-bound AAD
  construction (`vaulttier.AADKey(tier, key)`, folding tier into the AAD key-name
  component so the same key name in two tiers never produces identical ciphertext)
  used to live in `internal/vaulttier` here. That business logic has no reason to be
  in a general config/secret library, so it moved wholesale to `ffreis-platform-vaultctl`
  with the rest of `cmd/vaultctl` — do not recreate it here; it should only ever be
  reachable in this repo through pinned git history, not as live code.

## Structure

```
cmd/platform-configctl/   ← thin entry point
cmd/                       ← platform-configctl's Cobra CLI boundary (no business logic)
pkg/                       ← promoted for external import (e.g. by vaultctl's own repo)
pkg/store/                 ← DynamoDB abstraction (Store interface)
pkg/crypto/                ← AES-256-GCM encryption (Encryptor interface)
pkg/backup/                ← export/import format and checksum
pkg/logger/                ← structured zap logging with secret masking
pkg/profile/               ← named --profile default resolution, per-app path (shared)
pkg/guard/                 ← leak-control primitives shared with vaultctl: fingerprint,
                              env-truthy kill-switch parsing, empty/"-" value guard
internal/appconfig/        ← config resolution from env + flags (this binary only)
internal/diff/             ← live vs. snapshot comparison (this binary only)
internal/validate/         ← rule-based validation engine (this binary only)
```

## Build/run

```bash
export CONFIGCTL_TABLE=platform-config CONFIGCTL_SECRET_KEY="passphrase"
platform-configctl config get database_url --project payments --env prod
platform-configctl secret set api_key --project payments --env prod  # reads from stdin
```

`vaultctl` builds and runs from its own repo (`ffreis-platform-vaultctl`); see that
repo for its usage.

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
