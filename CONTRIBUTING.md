# Contributing to TacLab

Read [AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) before changing code. That file is mandatory.

## Toolchains

- Go 1.24.5 (`go.mod`)
- Node.js 22.14.0 (`.nvmrc`)
- npm 10.9.x (`web/package.json` `packageManager`)

## Checks

```bash
make fmt
make ci
```

`make bench` runs the header and obfuscation benches under `internal/tacacs/codec`.

Regenerate checked-in generated files with `make generate`. CI fails on drift.

`make check-registries` validates `api/operations.yaml` and `testdata/conformance/*.yaml` (duplicate IDs, required REST/MCP bindings). Missing bindings fail even before handlers exist.

## Scope

This repository is an implementation of the [canonical design](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md). Do not claim complete TACACS+ support while MUST conformance rows are unchecked.
