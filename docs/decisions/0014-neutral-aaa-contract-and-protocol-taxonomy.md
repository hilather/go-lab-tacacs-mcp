# ADR 0014: Neutral AAA Contracts and Protocol Taxonomy

Status: Accepted  
Date: 2026-08-14  
Decision owners: TacLab maintainers  
Related tasks: RAD-DOM-001, RAD-DOM-002, RAD-DOM-003, RAD-DOM-004, RAD-DOM-005, RAD-DOM-006, RAD-DOM-007  
Related conformance rows: PRJ-POL-001, PRJ-ERR-001, PRJ-TAC-001  
Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`

## Context

`internal/aaa` is described as protocol-independent, but current requests/results expose TACACS action, type, service, status, connection/session keys, and accounting flags. `domain.Transport` currently means TACACS `legacy` or `tls`, combining protocol and transport.

RADIUS needs UDP access/accounting roles, datagram request correlation, neutral authentication outcomes, typed response effects, and accounting records that are not TACACS flag bytes.

Extending `domain.Transport` with `radius_udp` would leak RADIUS into TACACS client-match YAML (`ParseTransport`, `ClientMatch.Transports`).

## Decision

Introduce additive closed domain types. Do **not** put RADIUS on `domain.Transport`.

1. `Protocol`: `tacacs`, `radius`, `http` (admin listener only).
2. `ListenerRole`: TACACS `aaa` (one socket, three families), RADIUS `access` / `accounting`, reserved `dynamic_authorization`.
3. `Carrier`: `tacacs_legacy_tcp`, `tacacs_tls`, `radius_udp`, `http_tcp`, reserved `radius_tls`.
4. Keep `domain.Transport` as TACACS `legacy` / `tls` only. `ParseTransport` still accepts only those values.
5. `RequestContext`: snapshot revision, endpoint/client, peer, opaque correlation ID, timestamps, and safe metadata.
6. Neutral authentication outcome, authorization effect, accounting record/result, and policy-trace contracts live in `internal/domain` so `aaa` and `policy/radius` can compile without an import cycle.

Keep current TACACS-facing interfaces (`BeginAuthentication`, `Authorize`, `RecordAccounting`) as compatibility wrappers while `internal/tacacs/server.Bridge` is migrated. RADIUS depends only on the neutral contracts (`AuthenticateAccess`, `RecordRADIUSAccounting`). No RADIUS package imports TACACS status/action/session types.

`domain.AVPair` stays TACACS-only (ADR 0015).

## Alternatives considered

### Extend `domain.Transport` with `udp` / `radius_udp`

Rejected. `ParseTransport` and client `match.transports` are public TACACS values. Extending `Valid()` would let RADIUS leak into TACACS match YAML.

### Big-bang rewrite of `aaa.Service`

Rejected. Highest TACACS regression risk. Wrappers first; Bridge exported signatures stay TACACS codec types.

### One giant `AAARequest` with optional fields

Rejected. Protocol-native metadata remains protocol-owned.

## Consequences

### Positive

- Shared credential verification, policy precedence, event publication, and traces can be reused.
- Protocol adapters remain responsible for wire/status/code mapping.
- TACACS migration can proceed incrementally with behavior-preserving adapter tests.

### Negative

- Some public internal types change additively and require import-boundary tests.
- Status/events must carry protocol, carrier, and role rather than overloading `transport`.

## Compatibility impact

TACACS listeners, `domain.Transport`, and existing `aaa` method signatures stay valid. RADIUS methods are additive.

## Migration

None for operators. Internal callers of `aaa` keep using TACACS wrappers until RAD-DOM-007.

## Test impact

- Import tests forbid `aaa` → `radius/codec` / `radius/udp` and `policy/radius` → `aaa`.
- TACACS goldens for `BeginAuthentication` / `Authorize` / `RecordAccounting` remain merge gates.

## Documentation impact

Taxonomy tables live in [docs/designs/radius-authentication.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-authentication.md) §3 and [docs/ARCHITECTURE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md).

## Revisit conditions

- A later ADR adds RADIUS/TLS (RadSec) or dynamic authorization.
- User/group RADIUS rule attachment is added (deferred; v1 `User`/`Group` stay TACACS-only).
