# Changelog

All notable changes to TacLab (`taclabd`) are documented here.

## [Unreleased]

### Documentation

- Operator-facing README with feature catalog, REST/MCP matrix, and a documentation map for every contract linked from the root page.
- [docs/QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md) — clone, `labgen`, Compose, UI, first REST and MCP calls.
- [docs/MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md) — Streamable HTTP contract plus **local** and **remote/hosted** client setup (Claude/Cursor/VS Code JSON, curl, Caddy/nginx, origin policy).
- [AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) §1.1 — first-time toolchain, lab bring-up, and MCP local/remote instructions for coding agents.
- GitHub Pages site at `https://hilather.github.io/go-lab-tacacs-mcp/` (`site/`).

## [1.0.0] — 2026-08-13

First tagged lab-appliance release. Module `github.com/hilather/go-lab-tacacs-mcp`. Image `ghcr.io/hilather/go-lab-tacacs-mcp`. This section is the full high-level delta from an empty repository.

### Protocol

- RFC 8907 core AAA: ASCII LOGIN, PAP, CHAP, MS-CHAP v1/v2, ENABLE (type ignored), ASCII CHPASS.
- Authorization: separate service and command evaluators, full common AV dictionary, vendor pairs preserved.
- Accounting: START, STOP, WATCHDOG, WATCHDOG+update; invalid flags → ERROR; SUCCESS only after ring accept.
- Legacy obfuscation, per-client secrets, single-connect, dual-stack LPM, fail-closed match ties.
- RFC 9887 TLS 1.3 mTLS on a distinct port; UNENCRYPTED required; no obfuscation; no 0-RTT; CRL + resume re-check.

### Compatibility

- SENDPASS / SENDAUTH / FOLLOW rejected or never emitted (`N/A_RFC_DEPRECATED`).
- Ticket lifetime: `0` or `168h` only ([ADR 0005](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0005-ticket-lifetime.md)).
- No TLS 1.3 cipher YAML ([ADR 0004](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0004-tls13-cipher-policy.md)).
- No RFC 7924 Cached Information ([ADR 0003](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0003-cached-information.md)).
- External PSK / RPK deferred ([ADR 0006](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0006-external-psk-rpk.md)).
- No `config.import`. Overlay is memory-only.

### Security

- Argon2id login/ENABLE; separate challenge secrets ([ADR 0002](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0002-password-kdf.md)).
- Typed secrets; canary matrix; reuse warning without exported fingerprints.
- Lab static bearer vs MCP OAuth PRM ([ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)).
- ASCII/PAP enablement is documented, not a compile warning ([ADR 0012](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md)).
- Bump `golang.org/x/text` to v0.39.0 (GO-2026-5970) and the Go toolchain to 1.25.12 for stdlib crypto/net fixes.
- Gitleaks allowlists published RFC MS-CHAP test vectors in `internal/credentials/testdata/` only.

### Admin surfaces

- REST `/api/v1` + OpenAPI 3.1 + embedded React UI.
- MCP 2026-07-28 Streamable HTTP on `POST /mcp` via `github.com/modelcontextprotocol/go-sdk` v1.7.0. Lab bearer, origin policy, and URI-only `subscriptions/listen` stay in-tree ([ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)).
- REST/MCP parity harness for `PARITY_REQUIRED` operations.

### Lab

- Optional Containerlab + Cisco IOL integration lab (`make cisco-lab`). Skips with an equipment-gap message when the operator image or Containerlab is absent; never vendors Cisco binaries. Live IOL drive uses the host `ssh` client (not `golang.org/x/crypto/ssh`).

### CI

- Cancel stale workflow runs; per-job timeouts; checksum-pinned gitleaks; `govulncheck` pinned; compose-lab on pull request, `main`, and tags.
- Agents must watch CI after every push and after every release tag ([AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) §9). A red tag is a release blocker: investigate, harden CI, then retag or patch-tag.
- Every tag publishes CHANGELOG-based release notes (all high-level changes since the previous tag) plus Ubuntu 24.04 and Rocky Linux 9 images.

### Deployment

- Non-root, read-only-root Compose lab; host 49 / 300 / 8080; TLS-only overlay.
- `make lab-test` LAB-* suite, restart restores baseline.

### Performance

- First freeze in `benchmarks/budgets.yaml` (Intel i7-8750H, Go 1.24.5).
- 10% latency / 15% alloc regression policy. Argon2id excluded from `make bench`.
- 10-minute 250-conn soak is an operator procedure, not a CI number in this freeze.

### Interop

- Required software peer: in-tree `internal/tacacs/testclient` (separate codec).
- Cisco and second-NOS rows: **skipped** unless the operator supplies an IOL image (`make cisco-lab`). See [docs/INTEROP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/INTEROP.md).

### Documentation

- Operator guide, maintenance policy, interop notes, generated conformance report with evidence IDs.
- `make check-registries` now includes the `-release` MUST/SHOULD gate.
