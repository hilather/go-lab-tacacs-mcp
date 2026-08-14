# Changelog

All notable changes to TacLab (`taclabd`) are documented here.

## [Unreleased]

### Configuration

- Baseline loader accepts `schema_version: 1` and `schema_version: 2`. v1 files migrate in memory to named listener structs; source files are never rewritten. v2 uses `listeners.tacacs.legacy` / `tacacs.tls` / `radius.access` / `radius.accounting` / `http`. RADIUS listeners default `enabled: false` (`max_packet_bytes` default **4096**). Mixed v1/v2 listener keys fail closed. `server.admin_only` and `security.radius_shared_secrets` are v2-only. v2 clients accept `endpoints[]` with `radius_shared_secret` purpose and role-specific RADIUS LPM indexes. Flatten TACACS fields are a projection of TACACS endpoints. `radius_policies` remain an unknown field. `config.export` still emits `schema_version: 1`.
- Compiled snapshots now carry RADIUS access and accounting LPM indexes plus an empty dictionary placeholder. v1 TACACS snapshot fields stay equivalent. Invalid RADIUS compile leaves the previous snapshot. Overlay client patches retain omitted RADIUS secrets.

### Runtime

- `taclabd serve` registers enabled RADIUS/UDP access and accounting listeners on the `internal/runtime.Registry` (bounded receive, worker pool, per-source rate, exact-response retransmission cache). Unknown or ambiguous sources are silently discarded using the compiled snapshot `RADIUSIndex`. The stub handler returns structurally valid Access-Reject / Accounting-Response (Message-Authenticator first). This is not PAP/CHAP and is not advertised as complete RADIUS. Default example YAML stays `enabled: false`.
- Readiness is snapshot + every required listener + at least one AAA listener (TACACS or RADIUS), unless `server.admin_only: true`. HTTP `system.status.get` still lists the three named sockets.

### Protocol

- In-tree RADIUS packet and raw-attribute framing (`internal/radius/codec`, `internal/radius/attribute`). One datagram, 20..4096 octets, ordered TLV / VSA preservation. Not advertised.
- Built-in IETF MVP RADIUS dictionary and packet-role checks (`attribute.Builtin`, version `builtin-mvp-1`). Unknown attributes stay raw. Message-Authenticator is allowed on Accounting-Request and required first on Access and Accounting responses. Named `Cisco-AVPair` is not added. Not advertised.
- RADIUS authenticators, User-Password hide/unhide, and Message-Authenticator HMAC-MD5 primitives (`internal/radius/crypto`). Access-Request Authenticator is a nonce. Constant-time compare. Stub UDP replies insert Message-Authenticator first, then the Response Authenticator. Inbound require-versus-allow MA policy and PAP/CHAP are later. Not advertised.

### Added

- RADIUS accounting record type (`RecordRADIUSAccounting`) writes to the event ring. `Acct-Session-Id` is stored as `acct_session_id` (string) and is never stuffed into the TACACS `session_id` uint32. Event queries may AND optional protocol, listener role, packet code, and outcome onto the existing category filter.

### Security

- Bump the Go toolchain to **1.25.13** for stdlib fixes published 2026-08-13 (`encoding/asn1` GO-2026-5972, `net/http` GO-2026-5026, `net` GO-2026-5942, `encoding/xml` GO-2026-6088).

### CI

- GitHub Pages deploy no longer tries to create the site with `GITHUB_TOKEN` (`configure-pages` `enablement: true` fails with `Resource not accessible by integration`). The site is enabled once by a repo admin; `make docs-check` rejects the forbidden enablement input.

### Documentation

- [ADRs 0013](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0013-add-radius-to-existing-taclab-process.md)–[0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md) accepted: RADIUS is in-process in `taclabd` but **not advertised**. [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) and `testdata/conformance/rfc2865.yaml` (plus rfc2866/2869/3579/5080 and `project-radius.yaml`) are `NOT_STARTED` / `DEFERRED_MAY` skeletons. TACACS `make check-registries -release` is unchanged.
- Operator-facing README with feature catalog, REST/MCP matrix, and a documentation map for every contract linked from the root page.
- [docs/QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md) — clone, `labgen`, Compose, UI, first REST and MCP calls.
- [docs/BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md) — first-setup of YAML users, groups, clients, tokens, secret files, and Compose wiring.
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
