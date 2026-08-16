# ADR 0024: RADIUS CoA/Disconnect — DAC Originate and Echo DAS

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-004  
Related conformance rows: PRJ-ACCT-002  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

RFC 5176 Dynamic Authorization is typically implemented by the NAS (DAS). TacLab is a lab AAA server, not a NAS. Operators need to kick a lab switch from REST/MCP. They do not need TacLab to pretend inbound CoA tears down a device session.

A later RadSec listener may accept Accounting-Start on TLS. CoA to a NAS is still a UDP datagram verified with the NAS UDP RADIUS secret.

## Decision

1. TacLab is primarily a **DAC**: REST/MCP originate CoA-Request or Disconnect-Request **to the NAS**. That is the only path that affects a device.
2. Optional inbound **DAS** (`listeners.radius.dynamic_authorization`, default off, UDP 3799) is a **lab fixture / RFC 5176 echo**. It mutates only the in-memory session index and never forwards to a NAS, never tears down a TACACS session, and never sends UDP to the NAS.
3. **DAC always uses the client's UDP RADIUS endpoint** for secret, `coa_destination`, and `nas_coa_port`. `SessionRecord.EndpointID` is index identity only — not the CoA secret key. A TLS Accounting-Start does not select the TLS secret for CoA. No UDP RADIUS endpoint → `invalid_argument` / `RADIUS_SECRET_MISSING`.
4. Handle-based send requires a session row (Accounting-Start + Acct-Session-Id). Explicit-attribute originate (`client_id` + destination + User-Name/Acct-Session-Id) covers access-only labs. Both paths use the UDP endpoint secret.
5. Accounting-On and Accounting-Off for a given UDP `EndpointID` + peer IP (and NAS-IP/NAS-Identifier when present) **delete** matching session-index rows.
6. Originate requests **omit** `expected_revision`. A present field is `invalid_argument` (reject unknown JSON). CoA is not overlay CAS.
7. New scope `radius:dynamic` for originate. `sessions.list` stays `state:read`. Raw `acct_session_id` requires `events:sensitive`. Example bootstrap `lab-admin` does not receive `radius:dynamic` unless a recipe adds it.
8. Message-Authenticator is required on every dynauth packet this program emits and on every inbound dynauth packet. No `allow_missing`. Unknown client or invalid MA → silent discard.
9. Session index is process memory, capped, wiped on `runtime.reset` / process exit ([ADR 0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md)).
10. Keep UDP **3799** off the public internet.

## Alternatives considered

### CoA-only inbound (TacLab as DAS only)

Rejected as the only mode. Operators need to kick a lab NAS from MCP. Inbound DAS does not affect a device.

### Use `SessionRecord.EndpointID` (possibly TLS) as the CoA secret

Rejected. The NAS verifies CoA with the UDP RADIUS secret.

### Accept-and-ignore `expected_revision` on originate

Rejected. Silent ignore is a foot-gun versus every other mutating TacLab op.

### Give `lab-admin` `radius:dynamic` by default

Rejected. Existing tokens stay denied for CoA (fail closed).

## Consequences

### Positive

- Device teardown has one honest path (DAC).
- Inbound :3799 cannot be mistaken for a session-kill if operator copy is followed.
- RadSec accounting cannot select the wrong secret for CoA.

### Negative

- Handle-based DAC requires Accounting-Start + Acct-Session-Id.
- TLS-only RADIUS clients cannot originate CoA until a UDP endpoint exists.
- Inbound DAS can confuse operators if UI copy is weak.

## Compatibility impact

No CoA listener or originate API ships in this documentation change. Existing accounting ring behavior is unchanged.

## Migration

None now. After the implementing PRs, operators who want inbound echo add the listener and `dynamic_authorization` role. DAC is always available once the operations exist; handle path needs accounting.

## Test impact

- DAC handle and explicit paths resolve secret/dest from `radiusEndpoint(client, "udp")`.
- Missing UDP endpoint → `RADIUS_SECRET_MISSING`.
- Accounting-On/Off flush matching rows.
- `expected_revision` present → `invalid_argument`.
- Scope missing → deny originate.
- Inbound: unknown client / invalid MA discard; session miss → NAK 503; never sends to a NAS.
- Independent testclient dynauth evidence. Shared-codec loopback is not sufficient.

## Documentation impact

OPERATOR and UI CoA pages must say inbound :3799 is an RFC 5176 test fixture and does not kick a device. [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) §8 keeps CoA still-deferred until implementation PRs.

## Revisit conditions

- Dynauth over RadSec is required.
- A product decision to forward inbound CoA to a NAS (that would be a different role).
