# TacLab 1.0 maintenance policy

Status: post-release contract  
Last updated: 2026-08-13

## Supported versions

| Surface | 1.0 |
|---|---|
| Config schema | `schema_version: 1` |
| REST | `/api/v1` |
| MCP | `2026-07-28` only |
| Image | `ghcr.io/hilather/go-lab-tacacs-mcp:<tag-or-digest>` |
| Go | 1.25.0 |
| Node | 22.14.0 |

Unknown YAML/JSON mutation fields remain errors. Adding a field is a minor change; changing meaning is a major change and needs an ADR.

## Dependency and security cadence

- Go and Node pins change only with a toolchain PR and `docs/generated/toolchain.md` regeneration.
- `make vuln` (`govulncheck`) on the release path.
- Image: `docker buildx build --sbom --provenance` at publish time (not a baked SPDX file in the source tree).
- Secret canaries and `make secrets` stay merge-blocking.

## Benchmark baseline refresh

- Source of truth: `benchmarks/budgets.yaml`.
- Refresh on the documented reference class (see that file) after a hot-path change or quarterly.
- Compare with `benchstat`. Investigate >10% latency or >15% alloc/bytes-per-op regressions ([TESTING_AND_BENCHMARKS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TESTING_AND_BENCHMARKS.md) §9).
- Argon2id cost is **not** in the ordinary budget. Do not weaken KDF to pass `make bench`.

## Conformance rerun triggers

Re-run `make check-registries` (includes `-release`) and the affected package tests when any of these change:

- RFC 8907/9887 codec, session, AAA, TLS, or client-match behavior.
- A MUST/SHOULD disposition or ADR.
- Independent testclient codec.
- Lab Compose ports or TLS profile.

Do not mark a row `PASS` without a new evidence ID. Do not claim complete TACACS+ if `check-registries -release` fails.

## Deprecation

- REST/MCP operations: add `EXEMPT_BY_ADR` or a new operation ID; do not silently remove a `PARITY_REQUIRED` binding.
- Config keys: reject the old name or accept it as an alias for one minor release, documented in CHANGELOG and an ADR.
- SENDPASS / SENDAUTH / FOLLOW stay rejected.

## Bug reports

Issues must include:

1. Reproduction (config sketch without secrets, packet or API request).
2. Affected conformance row IDs and/or operation IDs.
3. A regression test name that fails before the fix.

Flaky security, conformance, parity, or race tests block release. Do not quarantine them without an owner and expiry.
