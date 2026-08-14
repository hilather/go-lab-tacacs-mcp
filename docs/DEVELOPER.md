# TacLab developer workflow (1.0)

Status: contributor contract  
Last updated: 2026-08-13

Read [AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) first. This page is the 1.0 how-to for the merge gate.

## Package ownership

See [ARCHITECTURE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md). REST and MCP are adapters over `internal/api/operations`. TACACS listeners are adapters over `internal/aaa`. No adapter-to-adapter calls.

## Operation-first REST/MCP

1. Edit `api/operations.yaml` (or the Go registry — keep them in lockstep).
2. Implement once in `internal/api/operations`.
3. Bind REST and MCP in the same change (`PARITY_REQUIRED`).
4. Add `internal/api/parity` coverage.
5. `make generate` and `make check-registries`.

## Protocol conformance

1. Identify T89-* / T98-* IDs in [TACACS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TACACS_CONFORMANCE.md).
2. Add independent fixtures under `testdata/protocol` (testclient codec, not a shared-codec loopback as sole evidence).
3. Attach evidence IDs in `testdata/conformance/*.yaml`.
4. `make generate` rewrites `docs/generated/conformance.md`.
5. `make check-registries` runs `-release`: mandatory MUST rows must be `PASS` or `N/A_RFC_DEPRECATED`; SHOULD rows must be `PASS` or `DISPOSITIONED_SHOULD`. Evidence IDs need a known prefix (`unit:`, `golden:`, `fuzz:`, `race:`, `bench:`, `lab:`, `adr:`, `docs:`, `interop:`, `cmd:`) and named `Test*`/`Fuzz*`/`Benchmark*` symbols must exist. Structural-only: `go run ./tools/check-registries` (no `-release`).

Do not claim complete TACACS+ if `-release` fails.

## Fixtures and fuzz

- Golden bodies: `testdata/protocol/bodies/`.
- Fuzz seeds: `testdata/protocol/fuzz/` (TACACS) and `testdata/protocol/radius/fuzz/` (RADIUS framing). RADIUS crypto vectors: `testdata/protocol/radius/crypto/vectors.json`. Every parser defect adds a seed.
- `make fuzz-smoke` runs `Fuzz*` as unit tests.

## Regression and benches

- Policy: [TESTING_AND_BENCHMARKS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TESTING_AND_BENCHMARKS.md).
- Freeze: [benchmarks/budgets.yaml](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/benchmarks/budgets.yaml).
- `make bench` excludes Argon2id.

## Frontend

```bash
make web-install
make web-typecheck
make web-lint
make web-test
make web-build   # copies into internal/ui/dist
make web-e2e
```

Use the generated OpenAPI client only.

## Release evidence

```bash
make ci                 # includes make check-release-notes
make check-registries   # includes -release
make lab-test           # optional locally; CI compose-lab job on PRs, main, and tags
make cisco-lab          # optional Containerlab+IOL; SKIP exit 0 without TACLAB_IOL_IMAGE
```

GitHub Actions workflow: https://github.com/hilather/go-lab-tacacs-mcp/blob/main/.github/workflows/ci.yml

Required jobs for merge: `lint-test-build`, `compose-lab`, `govulncheck`, `gitleaks`, and the aggregating `ci-gate`.

The `pages` workflow deploys `site/` to GitHub Pages. It is not part of `ci-gate`, but a red `pages` run on `main` is still a defect. Do not “fix” it with `configure-pages` `enablement: true` (`GITHUB_TOKEN` cannot create the site). Enablement is documented in [MAINTENANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MAINTENANCE.md) §GitHub Pages. `make docs-check` rejects that input.

Publish notes go in [CHANGELOG.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CHANGELOG.md). The `## [X.Y.Z]` section must list **all high-level changes since the previous tag**. After tagging `vX.Y.Z`, watch the `ci` and `release` workflows until they pass ([AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) §9). If tag CI fails, investigate and harden the workflow or tests before the next tag. Every release must include:

- `make release-notes` → `dist/RELEASE_NOTES.md` (high-level CHANGELOG section + commits since the previous tag)
- Ubuntu 24.04 and Rocky Linux 9 images (`make image-ubuntu`, `make image-rocky`) plus the distroless default

Image SBOM/provenance is `docker buildx --sbom --provenance` at publish, not a tree-checked SPDX file.
