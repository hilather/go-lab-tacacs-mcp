# RADIUS Conformance and Completeness Matrix

Status: implementation checklist (not advertised as complete RADIUS)  
Normative baseline: RFC 2865, RFC 2866, RFC 2869, RFC 3579 (MA/EAP-Message validation only), RFC 5080  
Last updated: 2026-08-16  
Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`  
Binding ADRs: [0013](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0013-add-radius-to-existing-taclab-process.md)–[0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md) (shipped); [0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md)–[0029](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0029-user-group-radius-policy-attachment.md) (in-memory remaining-work program; `RAD-EXT-006` operator dictionaries shipped, other EXT rows later)  
Implementation design: [docs/designs/radius-authentication.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-authentication.md) (MVP); [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md) (remaining work)  
Operator residual limits: [docs/OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md) §1.1

MVP MUST rows are `PASS` with linked executable evidence, including Access-Challenge `R65-ACCESS-004` (independent `internal/radius/testclient` wire Challenge + EAP Identity/MD5). Tunneled EAP stays `DEFERRED_MAY` (`PRJ-EAP-003`). External FreeRADIUS `radclient` is **SKIP** when the binary is absent; that skip is not RADIUS PASS. `system.build.get` RADIUS status stays `partial` ([ADR 0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md)).

This file is a **lab-profile checklist**, not a completeness badge. Do **not** advertise complete RADIUS while tunneled EAP / persist / proxy / DTLS remain deferred, accounting is memory-only, external `radclient` is skipped, or any MVP row lacks evidence. Named `Cisco-AVPair` (`PRJ-CISCO-001`) is PASS on independent fixtures; an IOL skip is not that PASS.

## 1. Purpose

This file defines what “complete RADIUS support” will mean for TacLab. It is the human contract parallel to [docs/TACACS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TACACS_CONFORMANCE.md).

Do **not** claim complete RADIUS while tunneled EAP / persist / proxy / DTLS remain deferred, external `radclient` is skipped, or any MVP row lacks evidence. `system.build.get` RADIUS status stays `partial`.

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
| PRJ-CISCO-001 | PROJECT MUST | Named `Cisco-AVPair` (vendor 9, vendor-type 1) decode/encode | Independent `testclient` fixtures; named and raw reply forms same wire. IOL skip is not PASS | [x] |
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
| R65-ACCESS-004 | MUST | Access-Challenge only under complete state/security gate | Independent testclient wire Challenge + EAP Identity/MD5; State bind/TTL/consume-on-use ([ADR 0021](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0021-radius-access-challenge-state-gate.md)) | [x] |
| PRJ-POL-001 | PROJECT MUST | Policy result is deterministic and reply attributes are role/type validated | Default deny; compile-time packet-role legality | [x] |
| PRJ-POL-002 | PROJECT MUST | v2 user/group `radius_policy_id`; walk user → `effectiveGroups` → client → fallback → deny | v1 unknown-field reject; goldens; REST/MCP parity; [ADR 0029](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0029-user-group-radius-policy-attachment.md) | [x] |
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
| PRJ-UL-001 | PROJECT MUST | Access-Reject `reject_password_change_required` after good PAP/CHAP + `must_change_login`; no extra attrs | `AuthenticateAccess` rejects before policy; `wireAccessReason` allowlist; [§5.7](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-authentication.md). EAP must-change adds only generic EAP-Failure (same as bad password) | [x] |
| PRJ-MSCHAP-001 | PROJECT MUST | RADIUS MS-CHAPv1/v2 via RFC 2548 vendor 311 VSAs; independent RADIUS vectors; must_change Reject with no `MS-CHAP-Error` | `testdata/protocol/radius/mschap/` + independent `testclient` + live UDP; methods opt-in | [x] |
| PRJ-RADSEC-001 | PROJECT MUST | RADIUS/TLS 1.3 stream on TCP 2083 (mTLS, length-prefixed, secret required) | Independent `testclient` TLS client; [ADR 0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) | [x] |
| PRJ-RADSEC-002 | PROJECT MUST | DTLS and RADIUS/1.1 are not implemented | `DEFERRED_MAY` [ADR 0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) Revisit | deferred |
| PRJ-EAP-001 | PROJECT MUST | EAP-Message requires valid MA; Identity + EAP-MD5 terminate | Independent testclient wire Identity then MD5 then Accept | [x] |
| PRJ-EAP-002 | PROJECT MUST | Unknown EAP type → generic EAP-Failure + Access-Reject; no Challenge leak | PEAP/TLS/other fail closed | [x] |
| PRJ-EAP-003 | PROJECT MUST | Tunneled EAP / pass-through not implemented | `DEFERRED_MAY` [ADR 0022](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0022-radius-eap-identity-md5.md) | deferred |

## 8. Remaining-work program (implementation PRs flip rows as they land)

ADRs [0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md)–[0029](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0029-user-group-radius-policy-attachment.md) are accepted. Operator dictionaries (`RAD-EXT-006` / `PRJ-DICT-001`) are implemented. MS-CHAP is `PASS` as `PRJ-MSCHAP-001`. User/group RADIUS attachment is `PASS` as `PRJ-POL-002`. Identity+MD5 EAP and Access-Challenge (`R65-ACCESS-004`) are `PASS` with independent testclient wire evidence. Remaining inbound DAS is later in this stack. Do not invent `R3579-EAP-*` or `R5080-*` IDs. `system.build.get` RADIUS `conformance_status` stays `partial` even after this program's in-scope rows land ([ADR 0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md)).

Program names, seams, and sequencing: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md).

| Area | Task | Status now | Binding ADR | When status may change |
|---|---|---|---|---|
| Access-Challenge (`R65-ACCESS-004`) | `RAD-EXT-001` | `PASS` | [0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md) + [0021](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0021-radius-access-challenge-state-gate.md) | independent testclient wire Challenge + EAP |
| EAP Identity + EAP-MD5 termination | `RAD-EXT-002` | `PASS` (`PRJ-EAP-001` / `PRJ-EAP-002`) | [0022](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0022-radius-eap-identity-md5.md) | unknown types fail closed |
| Tunneled EAP (PEAP/TLS/TTLS) / pass-through | `RAD-EXT-002` residual | `DEFERRED_MAY` | [0022](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0022-radius-eap-identity-md5.md) | later tunneled-EAP ADR |
| RADIUS MS-CHAPv1/v2 | `RAD-EXT-003` / `PRJ-MSCHAP-001` | **PASS** (opt-in) | [0023](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0023-radius-mschap-vsas.md) | Independent `testdata/protocol/radius/mschap/` + `testclient` + live UDP. TACACS START fixtures are not evidence. MD4-era residual remains. |
| CoA/Disconnect DAC originate | `RAD-EXT-004` | **PASS** (`PRJ-COA-001`) | [0024](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0024-radius-coa-disconnect.md) | DAC uses the client's UDP RADIUS secret; handle needs Accounting-Start; explicit dest for access-only labs |
| Inbound DAS echo fixture | `RAD-EXT-004` | **PASS** (`PRJ-COA-002`) | [0024](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0024-radius-coa-disconnect.md) | default off; index-only; does not kick a NAS |
| RadSec TLS 1.3 TCP 2083 | `RAD-EXT-005` | still deferred | [0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) | implementing PR; not a thin TLS wrap of UDP |
| DTLS / RADIUS/1.1 | `RAD-EXT-005` residual | `DEFERRED_MAY` | [0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) Revisit | later transport ADR |
| Operator dictionaries (`PRJ-DICT-001`) | `RAD-EXT-006` | `PASS` | [0026](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0026-radius-operator-dictionaries.md) | TacLab YAML only; vendors 0/9/311 and `Cisco-AVPair` / `MS-CHAP-*` reserved; `DictionaryVersion` stays `builtin-mvp-1` when no operator file compiled |
| Named `Cisco-AVPair` (`PRJ-CISCO-001`) | `RAD-EXT-007` | **PASS** on independent fixtures | [0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md) (supersedes [ADR 0015](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0015-radius-codec-attribute-and-dictionary-boundary.md) decision 4 / IOL Revisit) | IOL listed as `interop:` only; skip is not PASS |
| RadSec TLS 1.3 TCP 2083 | `RAD-EXT-005` | `PRJ-RADSEC-001` PASS | [0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) | Lab RadSec; TLS 1.3 mTLS stream; PAP/CHAP only until EAP/MS-CHAP land; default listener off |
| DTLS / RADIUS/1.1 | `RAD-EXT-005` residual | `PRJ-RADSEC-002` `DEFERRED_MAY` | [0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) Revisit | later transport ADR |
| Operator dictionaries | `RAD-EXT-006` | still deferred | [0026](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0026-radius-operator-dictionaries.md) | implementing PR; vendors 0/9/311 reserved |
| Named `Cisco-AVPair` | `RAD-EXT-007` | still deferred | [0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md) (supersedes [ADR 0015](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0015-radius-codec-attribute-and-dictionary-boundary.md) decision 4 / IOL Revisit) | implementing PR; independent fixtures; IOL skip is not PASS |
| RADIUS proxying / realm routing | `RAD-EXT-008` | `DEFERRED_MAY` | [0028](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0028-defer-radius-proxying.md) | out of this program; no `proxy` YAML key |
| Persistent accounting | `RAD-EXT-009` | **cancelled this program** | [0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md) | later persist ADR only |
| User/group RADIUS rules | `RAD-EXT-010` / `PRJ-POL-002` | **PASS** | [0029](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0029-user-group-radius-policy-attachment.md) | v2 `users[].radius_policy_id` / `groups[].radius_policy_id`; walk user → `effectiveGroups` → client → fallback → deny |
| `must_change_login` (`PRJ-UL-001`) | — | `PASS` unchanged | [0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md) | stays Access-Reject; EAP may add only generic EAP-Failure teardown |
| `R79-MA-001` | — | `PASS` | [0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md) | EAP termination adds evidence later; MA/EAP-without-MA already PASS |

## 9. Evidence conventions

Each completed row must identify one or more of: `unit:`, `golden:`, `fuzz:`, `interop:`, `race:`, `bench:`, `docs:`, `adr:`, `lab:`, `cmd:`.

Tests generated by a TacLab client using the same codec are not sufficient as the only evidence. Shared-codec loopback against the production listener is not RADIUS PASS. Independent `internal/radius/testclient` UDP exchange is required. External `radclient` is recorded in [docs/INTEROP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/INTEROP.md); a skip is not PASS.

## 10. Operator residual limits (not completeness)

A green row in this file does **not** make TacLab a production RADIUS server. Residual limits are binding:

| Residual | Why it blocks a completeness claim |
|---|---|
| Lab appliance, single replica | Overlay, cache, journal, event ring, and (when they land) Challenge store / CoA index are process memory ([ADR 0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md)) |
| Memory-only accounting | Restart loses records; persist (`RAD-EXT-009`) is **cancelled** for this program ([ADR 0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md)) |
| UDP remains the default lab profile | RADIUS/UDP is still MD5-era and mostly cleartext. RadSec (RFC 6614 TLS 1.3 TCP 2083) is an **optional** stream listener, default off. It is not “UDP plus TLS.” DTLS/1.1 stay deferred. Keep **2083** and **3799** off the public internet unless intentionally published like TACACS 300 |
| Access-Challenge | Identity + EAP-MD5 only. State is memory-only, consume-on-use, TTL/bind/capacity fail-closed. `R65-ACCESS-004` `PASS` |
| EAP | Identity + EAP-MD5 terminate. Other types → generic EAP-Failure + Access-Reject. Tunneled EAP stays `DEFERRED_MAY` (`PRJ-EAP-003`) |
| Inbound CoA / Disconnect is an echo fixture | DAC originate kicks a NAS. Inbound :3799 DAS (default off) mutates the memory index only and never forwards ([ADR 0024](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0024-radius-coa-disconnect.md)) |
| RADIUS MS-CHAP is MD4-era | Opt-in `mschapv1`/`mschapv2` only. No `MS-CHAP-Error` / Password-Expired VSA. Independent RADIUS vectors, not TACACS fixtures |
| Named `Cisco-AVPair` | Shipped (`PRJ-CISCO-001` PASS) via independent fixtures ([ADR 0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md)). An IOL skip is **not** Cisco PASS and **not** RADIUS PASS |
| Operator dictionaries | TacLab YAML, local, size-capped, fail-closed ([ADR 0026](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0026-radius-operator-dictionaries.md)). Not FreeRADIUS `$INCLUDE`. Vendors 0/9/311 reserved |
| Proxying out | `DEFERRED_MAY` ([ADR 0028](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0028-defer-radius-proxying.md)) |
| External `radclient` / IOL skip | Skip is not PASS |
| `system.build.get` `partial` | Do not market “complete RADIUS” |

Operator onboarding and silent-discard troubleshooting: [docs/OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md).
