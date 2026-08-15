# TacLab 1.0 maintenance policy

Status: post-release contract  
Last updated: 2026-08-13 (Pages enablement + release watch + Ubuntu/Rocky variants)

## Supported versions

| Surface | 1.0 |
|---|---|
| Config schema | `schema_version: 1` (default) and `2` (named listeners; RADIUS UDP default off) |
| REST | `/api/v1` |
| MCP | `2026-07-28` only |
| Image | `ghcr.io/hilather/go-lab-tacacs-mcp:<tag-or-digest>` (also `:<tag>-ubuntu`, `:<tag>-rocky`) |
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

## GitHub Pages

The project site is the static tree in [`site/`](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/site), published to `https://hilather.github.io/go-lab-tacacs-mcp/` by [`.github/workflows/pages.yml`](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/.github/workflows/pages.yml).

`GITHUB_TOKEN` can **deploy** an existing Pages site (`pages: write` + `id-token: write`). It **cannot create** the site. `actions/configure-pages` `enablement: true` fails with `Resource not accessible by integration` ([actions/configure-pages#40](https://github.com/actions/configure-pages/issues/40)). Do not re-add that input. `make docs-check` rejects it.

A repo admin enables Pages **once**:

```bash
gh api --method POST repos/hilather/go-lab-tacacs-mcp/pages -f build_type=workflow
```

Settings equivalent: **Pages → Source → GitHub Actions**. After that, pushes to `main` that touch `site/` or the workflow deploy the artifact.

If the site is deleted, recreate it with the same `POST` (or `PUT` to switch `build_type` to `workflow`). Do not try to create it from the workflow.

## Release

Agents must follow [AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) §9.

1. Move **all** `[Unreleased]` high-level items in [CHANGELOG.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CHANGELOG.md) into `## [X.Y.Z] — YYYY-MM-DD` (the full operator-facing delta since the previous tag: behavior, security, breaking limits, interop, images). Leave `[Unreleased]` empty. Do not ship “see git log” as the notes.
2. `git tag -a vX.Y.Z -m "TacLab X.Y.Z"` and push the tag.
3. **Watch CI until it passes** (`ci` on the tag, then `release`). Do not stop while those runs are in progress or red. On failure, investigate the logs, fix the product or the workflow, **harden CI** so the same class of failure cannot recur, then retag or patch-tag.
4. The `release` workflow must publish:
   - GitHub Release notes from `make release-notes` (CHANGELOG section + `git log` since the previous tag).
   - `ghcr.io/hilather/go-lab-tacacs-mcp:vX.Y.Z` (distroless default)
   - `ghcr.io/hilather/go-lab-tacacs-mcp:vX.Y.Z-ubuntu` (Ubuntu 24.04)
   - `ghcr.io/hilather/go-lab-tacacs-mcp:vX.Y.Z-rocky` (Rocky Linux 9)

A tag without notes or without both distro images is not a release.
