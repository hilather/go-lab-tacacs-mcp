# Changelog

All notable changes to TacLab (`taclabd`) are documented here.

## [Unreleased]

Operator-facing closeout of the in-process RADIUS/UDP **lab profile** since 1.0.0. This is **not** a RADIUS completeness release and **does not** cut a tag. Product, module, binary, and image names are unchanged ([ADR 0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md)).

### Residual limits (prominent)

- Single-replica **lab appliance**. Overlay, RADIUS cache, accounting journal, and event ring are memory-only and vanish on restart or `runtime.reset`.
- RADIUS is **UDP on a controlled lab network only**. MD5/HMAC-MD5, spoofable datagrams, mostly cleartext attributes. Keep 1812/1813 off the public internet. No RadSec, DTLS, RADIUS/TCP, or RADIUS/1.1.
- Deferred: Access-Challenge, EAP method termination, CoA/Disconnect, RADIUS MS-CHAP, named `Cisco-AVPair` (waits on independent IOL vectors), custom dictionary files, user/group RADIUS rules, persistent accounting, proxying.
- `system.build.get` RADIUS `conformance_status` stays `partial`. External `radclient` / Cisco IOL skip is **not** RADIUS PASS. Do **not** advertise complete RADIUS.

### Configuration

- Baseline loader accepts `schema_version: 1` and `schema_version: 2`. v1 files migrate **in memory** to named listener structs; source files are never rewritten. Mixed v1/v2 listener keys fail closed.
- v2 uses `listeners.tacacs.legacy` / `tacacs.tls` / `radius.access` / `radius.accounting` / `http`. RADIUS listeners default `enabled: false` (`max_packet_bytes` default **4096**). `server.admin_only` and `security.radius_shared_secrets` are v2-only.
- v2 clients accept `endpoints[]` with a distinct `radius_shared_secret` purpose and role-specific RADIUS LPM indexes. Flatten TACACS fields are a projection of TACACS endpoints.
- v2 accepts `radius_policies` / `radius_reply_profiles` / `fallback_radius_policy_id` (client + optional fallback, default deny). User/group RADIUS fields remain unknown.
- `config.export` **never** emits v2 YAML for a v1 source without the explicit convert flag `normalize=true` (default false). A v2 source exports as v2.
- Invalid RADIUS compile leaves the previous snapshot. Overlay client patches retain omitted RADIUS secrets.

### Protocol

- In-tree RADIUS codec, IETF MVP dictionary (`builtin-mvp-1`), authenticators, User-Password hide/unhide, and Message-Authenticator. One datagram, 20..4096 octets. Named `Cisco-AVPair` is not added.
- Access-Request PAP and CHAP → compiled policy → Access-Accept or Access-Reject. Message-Authenticator first, then unmodified Proxy-State. No Access-Challenge.
- Accounting Start, Stop, Interim-Update, Accounting-On, Accounting-Off into the memory ring. Accounting-Response only after the ring accepts the record. Exact-response cache plus a semantic journal that excludes Acct-Delay-Time. Ambiguous identity is fail-open-to-ack and sample-capped.
- Message-Authenticator required on Access-Request by default; always inserted on Access and Accounting responses; validate-if-present on inbound Accounting-Request. Weaker Access mode is per-endpoint, warned, and badged.

### Runtime

- `taclabd serve` registers enabled RADIUS/UDP access and accounting listeners on `internal/runtime.Registry` (bounded receive, worker pool, per-source rate, retransmission cache). Unknown or ambiguous sources are silently discarded.
- Readiness is snapshot + every required listener + at least one AAA listener (TACACS or RADIUS), unless `server.admin_only: true`. RADIUS-only labs are legal. Default example YAML stays `enabled: false`.

### Admin surfaces

- `system.status.get` / `system.build.get` / `events.list` are protocol-aware. RADIUS `conformance_status` is `partial`.
- Client CRUD exposes canonical `endpoints` plus a flattened `protocols.radius` view.
- RADIUS diagnostics (`radius.access.test`, `radius.policy.evaluate`, `radius.attributes.list`) with REST/MCP parity. Access test uses the same `AuthenticateAccess` path as UDP and wipes passwords.
- UI status, clients, RADIUS test/explain, and event filters are protocol-aware. Insecure-compatibility badge when Message-Authenticator is not required.

### Lab

- Compose maps RADIUS/UDP host ports 1812/1813 and a distinct `lab_switches_radius_secret`. `labgen` writes combined and RADIUS-only schema v2 profiles (`configs/lab.example.v2.yaml` is the checked-in template). `labtest` proves combined, RADIUS-only, and TACACS-only readiness. Secrets stay on the host; they are not baked into images.

### Tests

- RADIUS conformance registries attach executable evidence. MVP MUST rows are `PASS` except Access-Challenge (`DEFERRED_MAY`). Independent `internal/radius/testclient` talks to a live UDP listener. External `radclient` is SKIP when the peer is not installed. RADIUS benches are recorded in `benchmarks/budgets.yaml`.

### Security

- Bump the Go toolchain to **1.25.13** for stdlib fixes published 2026-08-13 (`encoding/asn1` GO-2026-5972, `net/http` GO-2026-5026, `net` GO-2026-5942, `encoding/xml` GO-2026-6088).
- Distinct RADIUS shared-secret purpose, canaries, and closed metric labels (no User-Name, peer IP, or `client_id` on RADIUS series).

### CI

- GitHub Pages deploy no longer tries to create the site with `GITHUB_TOKEN` (`configure-pages` `enablement: true` fails with `Resource not accessible by integration`). The site is enabled once by a repo admin; `make docs-check` rejects the forbidden enablement input.

### Documentation

- [ADRs 0013](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0013-add-radius-to-existing-taclab-process.md)–[0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md) accepted: RADIUS is in-process in `taclabd` but **not advertised as complete**.
- [docs/OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md) — RADIUS onboarding, silent-discard troubleshooting, v1/v2 migration, upgrade/rollback, residual limits.
- [docs/CONFIGURATION.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md) and [docs/CANONICAL_DESIGN.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md) residual limits match shipped behavior (no stub replies; export convert is `normalize=true`).
- [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) — human contract parallel to TACACS. TACACS `make check-registries -release` is unchanged.
- [docs/QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md), [docs/BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md), [docs/LAB_DEPLOYMENT.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md), [docs/INTEROP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/INTEROP.md).
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
