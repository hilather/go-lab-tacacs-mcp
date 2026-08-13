# Contributing to TacLab

Read [AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) before changing code. That file is mandatory.

## Toolchains

- Go 1.25.0 (`go.mod`)
- Node.js 22.14.0 (`.nvmrc`)
- npm 10.9.x (`web/package.json` `packageManager`)

## Checks

```bash
make fmt
make ci
```

`make bench` runs hot-path benches under `internal/tacacs`, `internal/policy`, `internal/state`, and `internal/aaa`. Argon2id stays in `internal/credentials`. Freeze: [benchmarks/budgets.yaml](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/benchmarks/budgets.yaml).

Regenerate checked-in generated files with `make generate`. CI fails on drift.

`make check-registries` validates `api/operations.yaml` and `testdata/conformance/*.yaml` and runs the **1.0 `-release` gate** (mandatory MUST rows `PASS` / `N/A_RFC_DEPRECATED`; SHOULD rows `PASS` / `DISPOSITIONED_SHOULD`).

Developer workflow: [docs/DEVELOPER.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/DEVELOPER.md).

## Scope

This repository is an implementation of the [canonical design](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md). Do not claim complete TACACS+ support while `make check-registries` (`-release`) fails or a MUST row lacks evidence.
