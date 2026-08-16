# ADR 0022: Lab EAP Termination (Identity + EAP-MD5)

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-002, RAD-DOM-005  
Related conformance rows: R65-ACCESS-004, R79-MA-001, PRJ-UL-001  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

Shipped RADIUS treats EAP-Message as an integrity concern only: EAP-Message without valid Message-Authenticator is discarded; EAP-Message present on Access-Request is `reject_unsupported_method`. NAS 802.1X / wired EAP against TacLab always Rejects.

Tunneled methods (PEAP, EAP-TLS, EAP-TTLS, EAP-FAST, TEAP) need a TLS-in-EAP stack, server certificates inside EAP, fragment reassembly, and session resumption. That is a separate program.

[ADR 0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md) keeps `must_change_login` as Access-Reject. EAP still needs RFC 3579 conversation teardown.

Do not invent `R3579-EAP-*` row IDs.

## Decision

1. EAP **termination** is Identity (type 1) + EAP-MD5 (type 4) only. Unknown or unimplemented types emit generic EAP-Failure + Access-Reject. No PEAP, EAP-TLS, EAP-TTLS, EAP-FAST, or TEAP. No pass-through to an external EAP server.
2. Challenge (ADR 0021) is a prerequisite. Unimplemented types do **not** issue Challenge and do **not** store State.
3. `must_change_login` after a successful EAP-MD5 verify is Access-Reject `reject_password_change_required` and **also** carries a **generic EAP-Failure** identical to a bad-password or unknown-user EAP Reject. No Challenge, no State, no Microsoft Password-Expired VSA. Difference in `reason_code` is metrics/API-only, not a RADIUS-wire oracle.
4. Endpoint `allowed_authentication_methods` must **explicitly include** `eap`. Omitted or empty lists compile to `[pap, chap]` and reject EAP with `reject_unsupported_method` before issuing Challenge.
5. EAP-Message requires valid Message-Authenticator (already true). Concatenated EAP payload is size-bounded. Overflow is Access-Reject.
6. Do not invent `R3579-EAP-*` IDs. Attach evidence to `R65-ACCESS-004`, `R79-MA-001`, and project rows added by the implementing PR.

## Alternatives considered

### Terminate PEAP / EAP-TLS in the same program

Rejected. Certificate-tunneled methods are a separate PKI + TLS-in-EAP program.

### EAP pass-through / proxy to an external EAP server

Rejected. That is proxying (ADR 0028).

### Interactive EAP password change

Rejected. ADR 0019 is not reopened. Generic EAP-Failure is protocol termination, not interactive change.

### Expand the compile default to include `eap`

Rejected. That would silently enable EAP on every existing v2 client that omitted the method list.

## Consequences

### Positive

- Labs can run Identity + EAP-MD5 against TacLab without claiming tunneled EAP.
- Must-change stays non-oracular on the wire.

### Negative

- EAP-MD5 is weak; residual tables must say so.
- 802.1X PEAP/TLS clients still Reject.

## Compatibility impact

No EAP termination ships in this documentation change. Existing `reject_unsupported_method` for EAP-Message remains until the implementing PR. Compile default methods stay `[pap, chap]`.

## Migration

Operators who want EAP add `eap` to `allowed_authentication_methods` after the implementing PR. Rollback: omit `eap`.

## Test impact

- Independent `testclient` UDP Identity + MD5 conversation.
- Unknown type → EAP-Failure + Access-Reject; no Challenge leak.
- Must-change vs bad-password EAP Rejects are not distinguishable by EAP type or payload.
- Fuzz seed: Access-Request with State + EAP-Message.
- Shared-codec loopback is not sufficient.

## Documentation impact

[docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) §8 keeps EAP termination still-deferred until the implementing PR. Tunneled EAP stays `DEFERRED_MAY` under this ADR.

## Revisit conditions

- An operator needs PEAP / EAP-TLS / EAP-TTLS and accepts a separate PKI program.
- A user-lifecycle ADR reopens Challenge-based RADIUS password change.
