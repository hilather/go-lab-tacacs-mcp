# ADR 0016: RADIUS/UDP Controlled-Network Profile, Message-Authenticator, and Retransmission

Status: Accepted  
Date: 2026-08-14  
Decision owners: TacLab maintainers  
Related tasks: RAD-SEC-002, RAD-RUN-005, RAD-ACCESS-006, RAD-ACCT-004  
Related conformance rows: R79-MA-001, R65-ACCESS-004, R80-DUP-001, PRJ-SEC-001, PRJ-SEC-002, PRJ-ACCT-001  
Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`

## Context

RADIUS/UDP is widely interoperable but uses legacy MD5-based constructions, sends most attributes in clear text, is exposed to spoofing/reflection, and requires duplicate/retransmission handling. BlastRADIUS and the current RADEXT deprecation work make it inappropriate to present UDP as a generally secure transport.

TacLab is a lab appliance, and an initial UDP profile provides the fastest path to useful device interoperability. The runtime must not duplicate expensive credential work or accounting side effects on retransmission.

## Decision

Ship RADIUS/UDP access and accounting first under a controlled-network compatibility profile.

1. Message-Authenticator is required by default for Access-Request (`require_message_authenticator: true`) and always validated when present on Access **or** Accounting.
2. Access-Accept, Access-Reject, and Accounting-Response always insert Message-Authenticator first. Not configurable.
3. Inbound Accounting-Request Message-Authenticator is validate-if-present. Do not discard a valid MA just because the packet is Accounting-Request.
4. Any weaker per-endpoint Access compatibility mode (`allow_missing`) is explicit, warned in validation/status/UI, and tested. No global off switch.
5. `limit_proxy_state: true` defaults on new RADIUS endpoints.
6. Unknown or ambiguous clients, invalid authenticators, invalid Message-Authenticator, malformed packets, and overload are silently discarded where protocol/security rules require.
7. All sockets, buffers, queues, workers, rate limits, caches, challenge state, attributes, and event payloads are bounded.
8. Retransmission cache key is endpoint + role + source addr/port + receiving socket + code + identifier + request authenticator + declared-packet digest. Access TTL is clamped to 5–30s.
9. Accounting uses two layers: exact-response cache **and** a bounded semantic journal that excludes Acct-Delay-Time.
10. Ambiguous accounting identity (no Acct-Session-Id and no NAS-IP/NAS-Identifier) is a documented fail-open-to-ack exception: send Accounting-Response so the NAS does not retry-storm, sample-cap ring appends (`ambiguous_accounting_per_minute`), and never fill the shared event ring unbounded.
11. UDP is documented and surfaced as unsuitable outside secure/controlled networks. Secure transports (RadSec/DTLS/RADIUS/1.1) require a later ADR.
12. Access-Challenge is architecture-ready but does **not** ship. Types may exist; no provider ships. Row `R65-ACCESS-004` is `DEFERRED_MAY` with this ADR as evidence.
13. EAP method termination, CoA/Disconnect, proxying, MS-CHAP, custom dictionaries, and persistent accounting are deferred and require their own ADRs. EAP-Message without valid MA is discarded even if `require_message_authenticator` is false.

MD5/HMAC-MD5 exist solely because RADIUS/UDP requires them. Do not add a general MD5 helper to `internal/credentials` or `internal/domain`.

## Alternatives considered

### Require RadSec/TLS before any RADIUS

Rejected for the first lab release. UDP is the interop path; secure transport is a follow-on ADR (Q-011).

### Global switch to disable Message-Authenticator

Rejected. Weaker mode is per-endpoint only, warned, and tested.

### Discard Accounting-Request that carries Message-Authenticator

Rejected. FreeRADIUS 3.2.5+ `radclient` sends MA after BlastRADIUS. Validate-if-present; always emit MA on Accounting-Response.

### Fail-closed (no Accounting-Response) on ambiguous identity

Rejected as a retry-storm risk. Fail-open-to-ack with a sampled ring append is the documented exception to AGENTS.md 2.8.

### Ship Access-Challenge in MVP

Rejected unless bound, expiry, replay, provider, and secret-state tests are complete. Default is deferred.

## Consequences

### Positive

- The MVP is useful for labs without claiming modern transport security.
- Cache behavior becomes part of protocol correctness and reload semantics.
- BlastRADIUS-era clients can validate response MA.

### Negative

- Some legacy clients may require an explicit compatibility setting.
- UDP remains a cleartext, MD5-era transport.
- Ambiguous accounting can still emit a response without a new ring record.

## Compatibility impact

No change to TACACS listeners. RADIUS UDP defaults `enabled: false` until later PRs register listeners.

## Migration

Operators who need Access-Challenge, EAP termination, CoA, or RadSec wait for a later ADR. Program ADRs are now accepted: [0021](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0021-radius-access-challenge-state-gate.md) (Challenge), [0022](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0022-radius-eap-identity-md5.md) (EAP Identity+MD5), [0024](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0024-radius-coa-disconnect.md) (CoA), [0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) (RadSec TLS 1.3 TCP 2083). Those features are **not shipped**. `R65-ACCESS-004` stays `DEFERRED_MAY` until independent `internal/radius/testclient` wire evidence lands in an implementation PR. Do not flip the row from an ADR-only change. This ADR is **not** superseded.

## Test impact

- `R65-ACCESS-004` requires this ADR path as evidence until implemented.
- Invalid MA never reads, inserts, or purges the retransmission cache.
- Independent testclient and Q-010 `radclient` fixtures must validate response MA.
- Semantic journal: exact retry one event; delay-time retry one event + new response; legitimate interim not collapsed.

## Documentation impact

This ADR is the disposition for `R65-ACCESS-004` and the UDP security posture. Operator docs must keep the controlled-network warning. CANONICAL_DESIGN documents the accounting fail-open-to-ack exception.

## Revisit conditions

- Access-Challenge provider, bound state, and replay tests are complete. Program ADR is [0021](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0021-radius-access-challenge-state-gate.md); `R65-ACCESS-004` stays `DEFERRED_MAY` until independent testclient wire evidence.
- A RadSec / RADIUS/1.1 ADR is accepted. RadSec first-slice ADR is [0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) (not shipped). DTLS / RADIUS/1.1 stay deferred.
- BlastRADIUS or RADEXT guidance requires a stricter default.
