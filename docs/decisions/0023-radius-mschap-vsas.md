# ADR 0023: RADIUS MS-CHAPv1/v2 Microsoft VSAs

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-003, RAD-DOM-005  
Related conformance rows: PRJ-UL-001  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

TACACS already verifies MS-CHAPv1/v2 (`internal/credentials/mschap.go`) from START `data`. That is not RFC 2548 RADIUS VSA evidence. RADIUS Access today is PAP/CHAP only.

Microsoft vendor 311 nested TLVs (1-byte type + 1-byte length) are distinct from TACACS `PPP_id || challenge || response` framing.

[ADR 0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md) forbids Microsoft Password-Expired VSA and Access-Challenge for `must_change_login`.

## Decision

1. RADIUS MS-CHAP uses RFC 2548 Microsoft VSAs (vendor 311). Built-in named attributes, not an operator dictionary. Vendor 311 is reserved from operator files (ADR 0026).
2. `credentials.VerifyMSCHAPv1/v2` may be called internally after an exact 50→49 byte map. Evidence is independent RADIUS wire vectors under `testdata/protocol/radius/mschap/` plus independent `internal/radius/testclient` encode/decode. TACACS START `data` fixtures are not RADIUS evidence.
3. `must_change_login` after a good MS-CHAP verify is Access-Reject `reject_password_change_required` with **no** `MS-CHAP-Error`, **no** extra attributes, and **no** Challenge.
4. `mschapv1` and `mschapv2` are **opt-in** on `allowed_authentication_methods`. Omitted or empty lists stay `[pap, chap]`.
5. Conflicting evidence (User-Password or CHAP-Password or EAP-Message plus any MS-CHAP VSA; both v1 and v2 responses; wrong challenge length) is Access-Reject `reject_conflicting_auth`.
6. REST/MCP `radius.access.test` and `radius.policy.evaluate` method unions grow `mschapv1` / `mschapv2` in the **same** implementation PR as the wire path (`PARITY_REQUIRED`).
7. Wipe assembled MS-CHAP buffers. Never log, event, or return VSA material.

## Alternatives considered

### Reuse TACACS START fixtures as RADIUS evidence

Rejected. Framing differs. Shared-codec or TACACS loopback is not RADIUS PASS.

### Emit `MS-CHAP-Error` / Password-Expired VSA on must-change

Rejected. ADR 0019 decision 10 and `PRJ-UL-001`.

### Enable MS-CHAP by default on omitted method lists

Rejected. Existing v2 clients that omitted the list would silently gain MS-CHAP.

## Consequences

### Positive

- RADIUS MS-CHAP has project-owned RFC 2548 evidence.
- Diagnostics stay in parity with the wire.

### Negative

- MS-CHAP is MD4-era and weak; residual tables must say so.
- Operators must opt in per endpoint.

## Compatibility impact

No RADIUS MS-CHAP ships in this documentation change. TACACS MS-CHAP is unchanged.

## Migration

Operators who want RADIUS MS-CHAP add `mschapv1` / `mschapv2` after the implementing PR. Rollback: omit those tokens.

## Test impact

- Independent golden vectors and live-listener `testclient` acceptance of those bytes.
- Conflict matrix.
- Must-change Reject with no extra attrs / no `MS-CHAP-Error`.
- Canary: MS-CHAP material never in logs/events/errors.
- REST/MCP/parity tests in the same PR.

## Documentation impact

[docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) §8 keeps RADIUS MS-CHAP still-deferred until the implementing PR. Do not claim TACACS MS-CHAP as RADIUS evidence.

## Revisit conditions

- A user-lifecycle ADR accepts Microsoft Password-Expired / Challenge-based RADIUS change.
- Additional Microsoft VSAs are required for a documented lab recipe.
