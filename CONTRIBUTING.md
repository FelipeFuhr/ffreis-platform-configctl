# Contributing

## Repo Layout

- This repo follows the Go CLI archetype.
- Keep the executable entrypoint in `cmd/platform-configctl/main.go`.
- Keep application logic outside `main.go`; `main.go` should only call the top-level execute path.
- Keep automation in `scripts/`.
- Keep a single `Containerfile` at the repo root unless the repo genuinely needs multiple image definitions.
