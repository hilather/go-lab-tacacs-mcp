# Changelog

All notable changes to TacLab (`taclabd`) are documented here.

## [Unreleased]

### Dependencies

- Align the frontend Vite toolchain with `@vitejs/plugin-react` 6: Vite 8 (required peer; Vite 7 cannot resolve). Vitest 4.1 already accepts Vite 8.

### Protocol

- Bounded in-memory RADIUS Challenge State store (`internal/radius/runtime`): UDP source-IP and TLS cert binds, TTL, consume-on-use, capacity fail-closed. Continuation failures use `reject_invalid_state` / `reject_challenge_expired` / `reject_challenge_binding` / `reject_challenge_capacity`. Restart / `runtime.reset` wipe the store.
- RADIUS terminates EAP Identity (type 1) and EAP-MD5 (type 4) when a client opts in with `allowed_authentication_methods: […, eap]`. Omitted/empty lists still compile to `[pap, chap]`. Other EAP types (PEAP/TLS/TTLS/NAK/…) get generic EAP-Failure + Access-Reject (`reject_unsupported_eap_method`); oversize concatenated EAP-Message is `reject_eap_too_long`. First live Access-Challenge provider. `R65-ACCESS-004` is `PASS` with independent `internal/radius/testclient` wire evidence. `must_change_login` after a good MD5 is Access-Reject + the same generic EAP-Failure as a bad password. No PEAP/TLS. Secrets wiped.
- RADIUS Access-Request accepts opt-in Microsoft MS-CHAPv1/v2 VSAs (RFC 2548 vendor 311) with independent RADIUS wire vectors. Omitted `allowed_authentication_methods` still compile to `[pap, chap]`. Must-change after a good MS-CHAP verify is Access-Reject `reject_password_change_required` with no `MS-CHAP-Error` and no extra attributes. MS-CHAPv2 Accept includes `MS-CHAP2-Success`. TACACS START fixtures are not RADIUS evidence. MS-CHAP remains MD4-era and is not a complete-RADIUS claim.
- RADIUS access evaluation order is user policy, then each `effectiveGroups` policy (same membership/order as TACACS), then client `access_policy_id`, then optional `fallback_radius_policy_id`, then default deny ([ADR 0029](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0029-user-group-radius-policy-attachment.md)). First matching rule wins.
- Fail-closed operator RADIUS dictionaries (schema v2 `radius_dictionaries`). TacLab YAML only; local absolute files; size-capped. Cannot redefine built-in IETF attributes, cannot downgrade secret sensitivity, and cannot claim reserved vendor IDs `0` / `9` / `311` or names `Cisco-AVPair` / `MS-CHAP-*`. Remote files and FreeRADIUS `$INCLUDE` are rejected. `DictionaryVersion` stays exactly `builtin-mvp-1` when no operator file is compiled. This is **not** complete RADIUS.
- Named RADIUS `Cisco-AVPair` (vendor 9, vendor-type 1) decode/encode. Reply profiles accept `name: Cisco-AVPair` / `value: shell:priv-lvl=15` and the existing raw `{vendor: 9, code: 1, value_hex}` form; both produce the same wire. Unknown Cisco vendor-types stay raw. Evidence is independent `internal/radius/testclient` fixtures under `testdata/protocol/radius/cisco/`. `PRJ-CISCO-001` is PASS. Optional `make cisco-lab` RADIUS IOL snippet SKIP without `TACLAB_IOL_IMAGE`; a skip is not Cisco PASS and not RADIUS PASS. Do not vendor IOL.
- Optional RADIUS/TLS 1.3 (RadSec) listener: length-prefixed RADIUS packets (RFC 6613 §2.6) inside TLS 1.3 mTLS on TCP 2083 ([ADR 0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md)). Default `listeners.radius.radsec.enabled: false`.
- A client may have one RADIUS UDP endpoint and one RADIUS TLS endpoint. `certificate_only` is legal when a TACACS TLS **or** RADIUS TLS endpoint exists.
- `system.build.get` RADIUS standards add `RFC 6614`. Status stays `partial`. `PRJ-RADSEC-001` PASS; `PRJ-RADSEC-002` (DTLS/1.1) `DEFERRED_MAY`.

### RADIUS CoA / Disconnect (DAC)

- In-memory accounting session index fed by Start/Interim/Stop; Accounting-On/Off flush matching rows. Access-Accept never inserts. Wiped on `runtime.reset`.
- Originate CoA-Request / Disconnect-Request (RFC 5176 codes 40–45) from REST/MCP. Message-Authenticator required. Handle path needs Accounting-Start; explicit `client_id` + destination covers access-only labs.
- Both paths use the client's **UDP** RADIUS endpoint secret, `coa_destination`, and `nas_coa_port`. `SessionRecord.EndpointID` is not the secret key. No UDP endpoint → `RADIUS_SECRET_MISSING`.
- New scope `radius:dynamic` in the closed set. Example `lab-admin` does **not** receive it. `sessions.list` is `state:read`; raw `acct_session_id` needs `events:sensitive`.
- `expected_revision` is rejected on originate (not overlay CAS). No inbound DAS listener yet.

### Configuration

- v2 `listeners.radius.access` gains `challenge_ttl` (default `30s`, 5s–60s), `challenge_entries` (default `4096`, 16–65536), and `challenge_bytes` (default `1MiB`, 64KiB–8MiB). Accounting rejects those keys.
- Schema v2 accepts optional `users[].radius_policy_id` and `groups[].radius_policy_id`. Unknown policy ids fail compile (`CONFIG_YAML_INVALID`). Schema v1 still rejects those keys.
- Schema v2 additive `listeners.radius.radsec` (bind `0.0.0.0:2083`, `transport: tls`) and client `transport: tls` on `protocol: radius`. v1 documents reject those keys.

### Admin surfaces

- `radius.access.test` and `radius.policy.evaluate` method unions grow `mschapv1` / `mschapv2` (`PARITY_REQUIRED`). MS-CHAP material is wiped and omitted from replies.
- `users.create` / `users.update` / `groups.create` / `groups.update` accept optional `radius_policy_id` (omitted keeps; JSON `null` clears). List/get/export include the field on v2 views. REST and MCP share the same types. Unknown JSON is rejected. No UI selects in this change.
- `radius.attributes.list` includes `source` (`builtin` or `operator:<id>`). Metadata only; no values. `system.status.get` reports `dictionary_version`.

### Residual limits (prominent)

- `system.build.get` RADIUS `conformance_status` stays `partial`. Named `Cisco-AVPair` does not make TacLab complete RADIUS.
- RadSec is an optional TLS 1.3 stream on TCP 2083, default off — not “UDP plus TLS.” No DTLS, no RADIUS/1.1, no cleartext RADIUS/TCP.
- Shared secret is still required on RADIUS/TLS endpoints. The informal well-known value `radsec` is not a default.
- DAC CoA always uses the client’s **UDP** RADIUS endpoint. A TLS-only RADIUS client cannot originate CoA.

## [1.2.0] — 2026-08-16

User-lifecycle must-change lock and MCP client compatibility. This is **not** a RADIUS completeness release. `system.build.get` RADIUS `conformance_status` stays `partial`.

### Residual limits (prominent)

- In-LOGIN / in-ENABLE extra GETPASS is a **TacLab/vendor extension**, not RFC 8907 LOGIN (§5.4.2.1) or ENABLE (§5.4.2.6). RFC change-password remains **CHPASS**.
- RADIUS still has no Access-Challenge, Microsoft Password-Expired VSA, or named `Cisco-AVPair`. Must-change on RADIUS is Access-Reject `reject_password_change_required` only.
- Published PHCs and MCP/REST-set flags are overlay-only. YAML-set flags return on `runtime.reset` / restart; the YAML baseline is never rewritten.
- MCP owns fixture + assert + admin rotate. It cannot send TACACS CONTINUE or complete GETPASS. Hosted agents finish a change with `users.update` secret rotate.
- No `taclab.qa.*` tools.

### Protocol

- Fail-closed login-class lock (`must_change_login`): after a successful verify, ASCII LOGIN **may** continue with extra GETPASS new/confirm when the client allows `ascii_chpass` (or `allowed_methods` is empty); otherwise FAIL with `server_msg=Password change required` and no overlay mutation. PAP / CHAP / MS-CHAP FAIL with the same `server_msg`. The lock is identity-level — CHAP / MS-CHAP fail even though they verify challenge material. `must_change_login` does not apply to ENABLE. Combined account-expiry / disabled / restricted / unknown / wrong-password stay uniform FAIL (empty `server_msg`).
- In-ENABLE GETPASS new/confirm after a successful ENABLE verify when `must_change_enable` is set. Overlay-only PHC via `OverrideEnableVerifier`.
- RADIUS Access-Reject `reject_password_change_required` after a good PAP/CHAP verify while `must_change_login` is set (no extra attributes).

### Admin surfaces

- `users.create` / `users.update` / `users.get` / `users.list` and `config.export` expose top-level `must_change_login` / `must_change_enable` (default `false`). REST and MCP (`taclab.users.*`) share the same types. `authentication.test` `status` includes `must_change` (not a TACACS or RADIUS packet status). `radius.access.test` `reason_code` includes `reject_password_change_required`. Unknown JSON on user mutations is rejected.
- Users page shows `Must change login` / `Must change enable` badges and editor checkboxes. Authentication test displays status `must_change` with warn styling.
- `api.mcp.allow_legacy_clients` (default `false`): opt-in relaxation of the HTTP-level `MCP-Protocol-Version: 2026-07-28` pin. When enabled, requests with a missing or older header pass through to the official SDK transport, which negotiates the protocol version during `initialize` — this lets older-generation MCP clients (gateways/proxies such as MCPJungle) connect. `subscriptions/listen` still requires the pinned version.

### Documentation

- [ADR 0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/v1.2.0/docs/decisions/0019-force-password-change.md) — login-class lock and vendor-extension GETPASS contract.
- [docs/OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/v1.2.0/docs/OPERATOR.md) §14 copy-paste MCP recipes for must-change fixture, assert, rotate, disable, account window, groups, client restriction, tombstone/reveal, `allowed_methods`, `policy.evaluate`, and `runtime.reset`. Overlay vs YAML (K16) is documented on every must-change recipe. No compose fixture user.

## [1.1.0] — 2026-08-15

RADIUS/UDP **lab profile** in the existing `taclabd` process. This is **not** a RADIUS completeness release. Product, module, binary, and image names are unchanged ([ADR 0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md)).

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
- Gitleaks allowlists published RADIUS RFC/lab vectors under `testdata/protocol/radius/` only (not live Compose secrets).

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
