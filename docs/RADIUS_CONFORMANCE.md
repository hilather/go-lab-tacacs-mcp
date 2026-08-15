# RADIUS Conformance and Completeness Matrix

Status: implementation checklist (not advertised as complete RADIUS)  
Normative baseline: RFC 2865, RFC 2866, RFC 2869, RFC 3579 (MA/EAP-Message validation only), RFC 5080  
Last updated: 2026-08-14  
Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`  
Binding ADRs: [0013](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0013-add-radius-to-existing-taclab-process.md)–[0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md)  
Implementation design: [docs/designs/radius-authentication.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-authentication.md)  
Operator residual limits: [docs/OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md) §1.1

MVP MUST rows are `PASS` with linked executable evidence except Access-Challenge `R65-ACCESS-004`, which stays `DEFERRED_MAY` ([ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md)). Independent software-peer evidence is `internal/radius/testclient` on a live UDP listener. External FreeRADIUS `radclient` is **SKIP** when the binary is absent; that skip is not RADIUS PASS. `system.build.get` RADIUS status stays `partial`.

This file is a **lab-profile checklist**, not a completeness badge. Do **not** advertise complete RADIUS while Access-Challenge is deferred, EAP/CoA/RadSec/MS-CHAP are out of scope, accounting is memory-only, UDP is the only carrier, external `radclient` is skipped, or any MVP row lacks evidence.

## 1. Purpose

This file defines what “complete RADIUS support” will mean for TacLab. It is the human contract parallel to [docs/TACACS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TACACS_CONFORMANCE.md).

Do **not** claim complete RADIUS while Access-Challenge is deferred, external `radclient` is skipped, or any MVP row lacks evidence. `system.build.get` RADIUS status stays `partial`.

No agent may mark a row complete based only on source inspection or a third-party library claim.

## 2. Status rules

Use the same vocabulary as TACACS:

| Status | Meaning |
|---|---|
| `NOT_STARTED` | No implementation evidence; `evidence` must be empty |
| `IN_PROGRESS` | Implementation exists but required evidence is incomplete |
| `PASS` | Automated conformance evidence passes |
| `N/A_RFC_DEPRECATED` | The current RFC directs implementations away from the option; explicit rejection is tested |
| `DEFERRED_MAY` | Optional or gated feature deferred through an ADR; `evidence` must include `adr:docs/decisions/….md` |
| `DISPOSITIONED_SHOULD` | `SHOULD` not implemented; approved ADR documents why |
| `FAIL` | Known nonconformance; RADIUS-advertisement blocker when the row is mandatory |

Pack labels map as follows. There is no `deferred_adr` YAML field.

| Pack label | Registry status |
|---|---|
| `DEFERRED_BY_ADR` | `DEFERRED_MAY` with `evidence: [adr:docs/decisions/0016-radius-udp-security-retransmission-and-scope.md]` (or the ADR that actually defers the row) |
| `NOT_APPLICABLE` | `N/A_RFC_DEPRECATED` only when the RFC deprecates the behavior; otherwise `DEFERRED_MAY` with `adr:` evidence |

Row IDs use pack prefixes only: `R65-` (RFC 2865), `R66-` (RFC 2866), `R69-` (RFC 2869), `R79-` (RFC 3579), `R80-` (RFC 5080), `PRJ-` (project). Do not invent `R3579-*` or `R5080-*` IDs.

`make check-registries` (`-release`) still gates **TACACS** RFC 8907/9887 completeness. RADIUS `NOT_STARTED` MUST rows are not a TACACS 1.0 release blocker.

### 2.1 Machine-readable registry

| File | `rfc` | Prefix |
|---|---|---|
| `testdata/conformance/rfc2865.yaml` | `2865` | `R65-` |
| `testdata/conformance/rfc2866.yaml` | `2866` | `R66-` |
| `testdata/conformance/rfc2869.yaml` | `2869` | `R69-` |
| `testdata/conformance/rfc3579.yaml` | `3579` | `R79-` |
| `testdata/conformance/rfc5080.yaml` | `5080` | `R80-` |
| `testdata/conformance/project-radius.yaml` | `PROJECT` | `PRJ-` |

`make generate` rewrites [docs/generated/conformance.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/conformance.md). `make check-registries` fails if this document cites an ID that is missing from those YAML files.

## 3. Packet and attribute framing

| ID | Level | Requirement | Required implementation and evidence | Status |
|---|---|---|---|---|
| R65-PKT-001 | MUST | Enforce packet length/header bounds | Minimum 20, maximum 4096, padding and short-packet handling | [x] |
| R65-PKT-002 | MUST | Handle supported/unsupported Codes deterministically | Invalid code silently discarded | [x] |
| R65-ATTR-001 | MUST | Validate Type/Length/Value framing | Length ≥ 2 and within remaining declared payload | [x] |
| R65-ATTR-002 | MUST | Preserve ordered duplicate attributes | Order and duplicates survive decode/encode | [x] |
| R65-VSA-001 | MUST | Parse/encode VSA framing and preserve unknown vendor data | Vendor-Specific (26); unknown VSA payloads stay raw | [x] |
| R65-PROXY-001 | MUST | Preserve Proxy-State order/value in responses | Unmodified copy after Message-Authenticator | [x] |

## 4. Authentication and integrity

| ID | Level | Requirement | Required implementation and evidence | Status |
|---|---|---|---|---|
| R65-RAUTH-001 | MUST | Validate/generate request and response authenticators | Response Authenticator vectors; Access-Request authenticator is a nonce | [x] |
| R65-PAP-001 | MUST | Correct User-Password hide/unhide and block/length checks | Independent hide/unhide vectors; wipe plaintext | [x] |
| R65-CHAP-001 | MUST | Validate CHAP evidence/challenge selection | CHAP-Password length 17; CHAP-Challenge else Request Authenticator | [x] |
| R79-MA-001 | MUST | Validate/calculate Message-Authenticator | HMAC-MD5; EAP-Message requires valid MA; responses insert MA first | [x] |
| R69-MA-001 | MUST | Validate Message-Authenticator on Access-Request whenever present | RFC 2869 §5.14; not a substitute for R79-MA-001 | [x] |
| R69-MA-002 | MUST | Insert Message-Authenticator on Access responses before Response Authenticator | Independent testclient validates response MA | [x] |
| PRJ-SEC-001 | PROJECT MUST | Missing/invalid required Message-Authenticator silently discards | Bounded diagnostics; no cache mutation | [x] |
| PRJ-SEC-002 | PROJECT MUST | Unknown/ambiguous clients and invalid authenticators receive no useful response | Silent discard | [x] |

## 5. Access behavior

| ID | Level | Requirement | Required implementation and evidence | Status |
|---|---|---|---|---|
| R65-ACCESS-001 | MUST | Parse and validate Access-Request | Required identity/evidence; conflicting methods reject | [x] |
| R65-ACCESS-002 | MUST | Construct valid Access-Accept | Identifier, authenticators, Message-Authenticator first, reply attributes | [x] |
| R65-ACCESS-003 | MUST | Construct valid Access-Reject | Permitted reject attributes only | [x] |
| R65-ACCESS-004 | MUST | Access-Challenge only under complete state/security gate | Deferred by [ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md) | deferred |
| PRJ-POL-001 | PROJECT MUST | Policy result is deterministic and reply attributes are role/type validated | Default deny; compile-time packet-role legality | [x] |
| PRJ-ERR-001 | PROJECT MUST | Discard/reject/internal/overload mapping is stable and non-oracular | Frozen reason_code table | [x] |

## 6. Accounting behavior

| ID | Level | Requirement | Required implementation and evidence | Status |
|---|---|---|---|---|
| R66-PKT-001 | MUST | Validate Accounting-Request and its authenticator | Verify before side effects | [x] |
| R66-RESP-001 | MUST | Construct exact Accounting-Response | Identifier copy; Message-Authenticator first | [x] |
| R66-STAT-001 | MUST | Map declared Acct-Status-Type values | Start, Stop, Interim-Update, Accounting-On, Accounting-Off | [x] |
| R69-ACCT-002 | MUST | Interim accounting, gigaword counters, Event-Timestamp, Acct-Interim-Interval | Semantic journal includes Event-Timestamp and counters | [x] |
| PRJ-ACCT-001 | PROJECT MUST | Retransmission replays exact response and emits one accounting event | Exact cache plus semantic journal excluding Acct-Delay-Time | [x] |
| PRJ-ACCT-002 | PROJECT MUST | Accounting/event storage is bounded, redacted, and memory-only | Journal/ring caps; ambiguous-identity sample budget | [x] |

## 7. Runtime and compatibility

| ID | Level | Requirement | Required implementation and evidence | Status |
|---|---|---|---|---|
| R80-DUP-001 | MUST | Duplicate/retransmission behavior is deterministic and bounded | Exact-response cache; pending discard; changed-RA purge | [x] |
| PRJ-RUN-001 | PROJECT MUST | Listener queues/workers/cache/state/output have hard limits and recover after overload | `drop_overload`; saturation metrics | [x] |
| PRJ-RUN-002 | PROJECT MUST | One datagram binds to one endpoint, secret handle, snapshot revision, and policy view | Role-specific LPM | [x] |
| PRJ-CFG-001 | PROJECT MUST | Strict v1 migrates deterministically; strict v2 rejects unknown/mixed syntax | v1 goldens unchanged | [x] |
| PRJ-TAC-001 | PROJECT MUST | Existing TACACS legacy/TLS conformance remains green | TACACS registries stay PASS on shared-package PRs | [x] |
| PRJ-PAR-001 | PROJECT MUST | REST/MCP/UI generated parity remains green | Same-change operations registry + generate | [x] |

## 8. Deferred features (no extra row IDs)

These areas stay out of the first advertised RADIUS release. They require a later ADR. EAP *termination* is a note, not a new ID, until an EAP ADR. Do not add `R3579-EAP-*` or other invented IDs.

| Area | Status target | Required ADR before implementation |
|---|---|---|
| Access-Challenge (`R65-ACCESS-004`) | `DEFERRED_MAY` | [ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md) (accepted; implementation gated) |
| EAP method termination / pass-through | deferred | Method/state/certificate/security and interop design |
| CoA / Disconnect (RFC 5176) | deferred | Dynamic authorization listener, authorization, replay, and session index |
| RADIUS proxying | deferred | Routing, loop detection, Proxy-State, secret domains, and failure design |
| RADIUS/TCP, RadSec/TLS, DTLS, RADIUS/1.1 | deferred | Current-standards transport selection and lifecycle/security design |
| Persistent accounting | deferred | Durability, backpressure, retention, privacy, migration, and operations |
| Arbitrary custom dictionaries | deferred | Trust, limits, validation, reload, sensitivity metadata |
| Named `Cisco-AVPair` decoding | deferred | Independent Cisco IOL vectors (user decision 2026-08-14) |
| RADIUS MS-CHAPv1/v2 | deferred | Credential and VSA evidence distinct from TACACS MS-CHAP |

## 9. Evidence conventions

Each completed row must identify one or more of: `unit:`, `golden:`, `fuzz:`, `interop:`, `race:`, `bench:`, `docs:`, `adr:`, `lab:`, `cmd:`.

Tests generated by a TacLab client using the same codec are not sufficient as the only evidence. Shared-codec loopback against the production listener is not RADIUS PASS. Independent `internal/radius/testclient` UDP exchange is required. External `radclient` is recorded in [docs/INTEROP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/INTEROP.md); a skip is not PASS.

## 10. Operator residual limits (not completeness)

A green row in this file does **not** make TacLab a production RADIUS server. Residual limits are binding:

| Residual | Why it blocks a completeness claim |
|---|---|
| Lab appliance, single replica | Overlay, cache, journal, and event ring are process memory |
| Memory-only accounting | Restart loses records; no durable sink |
| UDP controlled-network only | MD5-era, spoofable, mostly cleartext; RadSec/DTLS/RADIUS/1.1 deferred |
| Access-Challenge deferred | `R65-ACCESS-004` `DEFERRED_MAY` |
| EAP termination deferred | MA/EAP-Message validation only |
| CoA / Disconnect deferred | RFC 5176 out of profile |
| RADIUS MS-CHAP deferred | TACACS MS-CHAP is not RADIUS evidence |
| Named `Cisco-AVPair` deferred | Waits on independent IOL vectors; raw VSA only |
| Built-in dictionary only | No operator dictionary files |
| External `radclient` / IOL skip | Skip is not PASS |
| `system.build.get` `partial` | Do not market “complete RADIUS” |

Operator onboarding and silent-discard troubleshooting: [docs/OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md).
