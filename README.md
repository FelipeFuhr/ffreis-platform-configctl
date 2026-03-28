# platform-configctl

Control plane CLI for all platform configuration state. Manages scoped configs
and secrets backed by DynamoDB. Secrets are encrypted with AES-256-GCM.

---

## Requirements

| Requirement | Detail |
|---|---|
| Go | 1.25+ |
| AWS credentials | Any standard AWS credential chain |
| DynamoDB table | Must exist before use |
| `CONFIGCTL_TABLE` | Required env var — table name |
| `CONFIGCTL_SECRET_KEY` | Required for all secret operations |

---

## Installation

```bash
make install
# or
go install github.com/ffreis/platform-configctl@latest
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `CONFIGCTL_TABLE` | Yes | DynamoDB table name |
| `CONFIGCTL_SECRET_KEY` | For secrets | Passphrase for AES-256-GCM key derivation |
| `CONFIGCTL_OLD_SECRET_KEY` | Rotation only | Previous passphrase during key rotation |
| `CONFIGCTL_LOG_LEVEL` | No | `debug`, `info`, `warn`, `error` (default: `info`) |
| `AWS_DEFAULT_REGION` | Recommended | AWS region |
| `AWS_PROFILE` / standard chain | No | Any AWS credential mechanism works |

---

## DynamoDB Table Schema

Create the table once (Terraform or `aws` CLI):

```bash
aws dynamodb create-table \
  --table-name platform-config \
  --attribute-definitions \
    AttributeName=PK,AttributeType=S \
    AttributeName=SK,AttributeType=S \
  --key-schema \
    AttributeName=PK,KeyType=HASH \
    AttributeName=SK,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST
```

Key convention:
- `PK = PROJECT#{project}#ENV#{env}`
- `SK = CONFIG#{key}` or `SECRET#{key}`

---

## Commands

### Config

```bash
# Get a config value (exits 2 if not found)
platform-configctl config get database_url --project payments --env prod

# Set a config value (idempotent — skips write if value unchanged)
platform-configctl config set database_url "postgres://..." --project payments --env prod

# List all config values
platform-configctl config list --project payments --env prod --output table

# Delete a config key (idempotent — warns and exits 0 if not found)
platform-configctl config delete database_url --project payments --env prod
```

### Secrets

Secret values are **always read from stdin** — never from CLI arguments — to
prevent leakage via shell history or `ps`.

```bash
# Set a secret (reads from stdin)
echo -n "s3cr3t" | platform-configctl secret set stripe_key \
  --project payments --env prod

# Get secret metadata (value masked)
platform-configctl secret get stripe_key --project payments --env prod

# Reveal the decrypted value
platform-configctl secret get stripe_key --project payments --env prod --reveal

# List secrets (keys only, values always ***)
platform-configctl secret list --project payments --env prod

# Delete a secret
platform-configctl secret delete stripe_key --project payments --env prod
```

### Backup / Export / Import

```bash
# Export configs to a JSON backup file
platform-configctl backup export \
  --project payments --env prod \
  --output payments-prod.json

# Export configs and secrets (secrets stored as ciphertext)
platform-configctl backup export \
  --project payments --env prod \
  --include-secrets \
  --output payments-prod-full.json

# Dry-run import (validate but do not write)
platform-configctl backup import \
  --input payments-prod.json \
  --dry-run

# Import (safe overwrite using stored versions)
platform-configctl backup import \
  --input payments-prod.json \
  --overwrite
```

### Diff

Compare live state to a backup snapshot without modifying anything:

```bash
platform-configctl diff \
  --project payments --env prod \
  --input payments-prod.json
```

Output prefix:
- `+` key exists in file but not live (would be added)
- `~` key differs between live and file (would be modified)
- `-` key exists live but not in file (untouched by import)

Secret values always display as `<encrypted>`.

### Validate

Run validation rules against all config items:

```bash
platform-configctl validate --project payments --env prod
```

### Diagnostics

```bash
# Print the resolved IAM caller identity
platform-configctl whoami
```

---

## Global Flags

```
--project    string   Project name (required per command)
--env        string   Environment: dev, staging, prod (required per command)
--region     string   AWS region (overrides AWS_DEFAULT_REGION)
--table      string   DynamoDB table name (overrides CONFIGCTL_TABLE)
--log-level  string   debug|info|warn|error
--output     string   text|json|table (default: text)
```

---

## Security Notes

- **Plaintext secrets never appear in logs.** All secret values are masked as `***`.
- **Secret key material is never logged.** Not even at debug level.
- **Secrets are read from stdin only.** This prevents shell history and `ps` leakage.
- **Encryption**: AES-256-GCM, key derived via Argon2id from `CONFIGCTL_SECRET_KEY`.
- **AAD** (additional authenticated data) binds each ciphertext to its
  `project+env` location, preventing ciphertext transplant attacks.
- **Least privilege**: grant read-only DynamoDB permissions for CI. Write
  permissions are only needed for `set`, `delete`, and `import`.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (I/O, AWS, validation, etc.) |
| `2` | Key not found (get on absent key) |

---

## Development

```bash
make tidy          # go mod tidy + verify
make build         # compile binary to bin/
make test          # run all tests
make test-short    # unit tests only (no AWS)
make lint          # golangci-lint
make check         # tidy + vet + test-short
```

---

## Architecture

```
main.go
cmd/                 Cobra CLI boundary — no business logic
internal/
  appconfig/         Config resolution from env + flags
  store/             DynamoDB storage abstraction (Store interface)
  crypto/            AES-256-GCM encryption (Encryptor interface)
  backup/            Export/import format and checksum verification
  diff/              State comparison (live vs snapshot)
  validate/          Rule-based validation engine
  logger/            Structured zap logging with secret masking
```
