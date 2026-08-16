# ADR 0021: RADIUS Access-Challenge State Gate

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-001, RAD-DOM-006, RAD-DOM-008  
Related conformance rows: R65-ACCESS-004, PRJ-UL-001  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

[ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md) deferred Access-Challenge until bound state, expiry, replay, provider, and secret-state tests exist. Types already exist (`codec.CodeAccessChallenge`, `domain.AuthChallenge`, dictionary `State`). No Challenge is advertised. Row `R65-ACCESS-004` is `DEFERRED_MAY` with ADR 0016 as evidence.

EAP termination requires Access-Challenge. [ADR 0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md) keeps `must_change_login` as Access-Reject with no Challenge and no extra attributes for PAP/CHAP/MS-CHAP.

## Decision

1. Access-Challenge is a real provider behind a complete **in-memory** state gate. No Challenge is advertised until the gate tests are green and independent `internal/radius/testclient` wire evidence exists.
2. `R65-ACCESS-004` stays `DEFERRED_MAY` through the store-only implementation. The first live-listener Challenge/EAP testclient evidence flips the row to `PASS`. This ADR is the design record; do not flip the row in a documentation-only change.
3. `ChallengeStore` lives in carrier-neutral `internal/radius/runtime`. Bind is a tagged union (`udp_ip` | `tls_cert`). Listeners hold a pointer created in `cmd/taclabd/serve.go`. Do not put the shared table under `udp/`.
4. State is single-use per step, TTL-bounded, capacity fail-closed (no evict-to-admit), bound to endpoint + client + bind kind. Unknown or expired State is Access-Reject. Forged client State never creates a record.
5. `must_change_login` remains Access-Reject `reject_password_change_required`. Do not evaluate policy. Do not consult a Challenge provider ([ADR 0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md) decision 10).
6. PAP, CHAP, and MS-CHAP one-shot success never return `challenge` in this program.
7. Challenge State is `SensitivitySecret`. Never log, event, or metric-label the raw value.
8. Empty / omitted `allowed_authentication_methods` on an access role still compiles to `[pap, chap]`. New methods are opt-in.

## Alternatives considered

### Ship Challenge types-without-provider as done

Rejected. ADR 0016 forbids advertising until the gate and testclient evidence exist.

### Use Access-Challenge to finish `must_change_login`

Rejected. ADR 0019 and `PRJ-UL-001` are explicit: RADIUS is Reject, no Challenge, no Password-Expired VSA.

### Put the store under `internal/radius/udp`

Rejected. That would force `radius/tls` to import `udp`.

## Consequences

### Positive

- EAP (ADR 0022) has a reusable gate on UDP and later RadSec.
- Must-change stays a non-oracular Reject.

### Negative

- Challenge state dies on restart / `runtime.reset`.
- `allow_missing` Message-Authenticator plus Challenge is a lab foot-gun; default remains `required`.

## Compatibility impact

No production Challenge is emitted by this ADR. Existing PAP/CHAP Accept/Reject and `must_change` Reject stay unchanged.

## Migration

None for operators. Challenge knobs land in a later implementation PR, default-off relative to today's wire.

## Test impact

- Unit: issue / consume / replay / expiry / capacity / bind mismatch.
- `AuthenticateAccess` still rejects must-change without Challenge.
- Independent testclient UDP Challenge then continuation is required before `R65-ACCESS-004` becomes `PASS`.
- Race: concurrent continuations of the same State.
- Bench: `BenchmarkRadiusChallengeLookup`.
- Shared-codec loopback is not sufficient evidence.

## Documentation impact

[docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) keeps `R65-ACCESS-004` `DEFERRED_MAY` until the implementing PR attaches testclient evidence. MVP design §5.7 is amended in the first PR that emits Access-Challenge.

## Revisit conditions

- Independent testclient wire Challenge/EAP evidence is green (then flip `R65-ACCESS-004` to `PASS`).
- A later user-lifecycle ADR reopens Challenge-based RADIUS password change.
