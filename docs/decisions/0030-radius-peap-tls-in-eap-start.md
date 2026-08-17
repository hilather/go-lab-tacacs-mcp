# ADR 0030: Start PEAP (outer type 25 + TLS-in-EAP)

Status: Accepted  
Date: 2026-08-17  
Decision owners: TacLab maintainers  
Related tasks: RAD-PEAP-001, RAD-PEAP-002  
Related conformance rows: PRJ-EAP-002, PRJ-EAP-003  
Source: revisits [ADR 0022](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0022-radius-eap-identity-md5.md)

## Context

[ADR 0022](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0022-radius-eap-identity-md5.md) terminates EAP as Identity (type 1) + EAP-MD5 (type 4) only. Unknown types, including PEAP (type 25), emit generic EAP-Failure + Access-Reject. That remains the fail-closed default.

An operator now wants TacLab to **start** a PEAP program: outer EAP PEAP plus a server-authenticated TLS 1.3 tunnel that will later carry an inner EAP method. Complete PEAPv0/EAP-MSCHAPv2, PEAPv1/GTC, PEAP-EAP-TLS, crypto-binding, session resumption, and Windows/wpa_supplicant interop are a later increment (`RAD-PEAP-002`).

This ADR records the revisit of ADR 0022’s “no PEAP” rule. It does **not** flip RADIUS `conformance_status` off `partial`. `PRJ-EAP-003` stays `DEFERRED_MAY` until a complete tunneled method is evidenced.

## Decision

1. **Reopen PEAP as an opt-in start.** Endpoint `allowed_authentication_methods` may include `peap`. Omitted or empty lists still compile to `[pap, chap]`. `eap` still means Identity + EAP-MD5 only.
2. **Identity selects the next method.** If `peap` is allowed, Identity issues EAP-Request/PEAP Start (type 25, RFC 5216 Start flag, PEAPv0). Else if `eap` is allowed, Identity issues EAP-MD5 as today. Type 25 without `peap` stays generic EAP-Failure + Access-Reject and does not store State (`PRJ-EAP-002`).
3. **TLS-in-EAP lives in `internal/radius/eap/peap`.** The first increment ships: type 25, flags L/M/S + version nibble, PEAP Start encoding, and `NewServer` with TLS 1.3 only (cipher policy [ADR 0004](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0004-tls13-cipher-policy.md)). `HandshakeWithClient` proves a server-authenticated TLS 1.3 tunnel that will carry inner EAP. Inner EAP is not interpreted.
4. **Continuation after PEAP Start is fail-closed in this increment.** The Start Challenge is stored. A type-25 continuation is generic EAP-Failure + Access-Reject (`RAD-PEAP-002` owns handshake pump + inner method).
5. **Do not grow `radius.access.test` / `radius.policy.evaluate` `method.type` to `peap` in this increment.** Policy match tokens stay `password`/`pap`/`chap`/`mschapv1`/`mschapv2`/`eap`. PEAP is still EAP at the policy layer.
6. **Do not claim complete PEAP or complete RADIUS.** `PRJ-EAP-003` stays `DEFERRED_MAY`. `system.build.get` RADIUS `conformance_status` stays `partial`.
7. No EAP pass-through, EAP-TTLS, TEAP, EAP-FAST, or standalone EAP-TLS.

## Alternatives considered

### Treat `eap` as PEAP

Rejected. Existing labs that opted into Identity+MD5 would silently change conversation shape.

### Ship full PEAPv0/EAP-MSCHAPv2 in the same change

Rejected. That is `RAD-PEAP-002`. This ADR is start-of-program only.

### Leave ADR 0022 untouched and implement PEAP anyway

Rejected. A documented revisit is required.

## Consequences

### Positive

- Labs can opt into outer PEAP Start without enabling PEAP on every existing `eap` client.
- TLS-in-EAP framing and a TLS 1.3 server are testable without claiming inner-method completeness.

### Negative

- A PEAP Start Challenge is not yet a working 802.1X login. Clients that send ClientHello after Start still Reject.
- Operators must add `peap` explicitly.

## Compatibility impact

Existing `eap` conversations are unchanged. Type 25 without `peap` still fail-closes. Compile default methods stay `[pap, chap]`.

## Migration

Operators who want PEAP Start add `peap` to `allowed_authentication_methods` after the implementing change. Rollback: omit `peap`.

## Test impact

- `ParseRADIUSAuthMethods` accepts `peap`; empty/omitted lists stay `[pap, chap]`.
- Identity + `peap` issues Access-Challenge whose EAP-Message is type 25 with the Start flag.
- Type 25 + `eap` only (no `peap`) still Rejects without State.
- `NewServer` + `HandshakeWithClient` complete a TLS 1.3 handshake and return server TLS records. Tests drive the shipped functions, not a mock of the unit under test.
- Shared-codec loopback is not PEAP evidence.

## Documentation impact

[docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) records the start increment and keeps `PRJ-EAP-003` deferred. Residual tables must say PEAP is Start-only, not complete PEAPv0.

## Revisit conditions

- Inner EAP (PEAPv0/EAP-MSCHAPv2 or PEAPv1/GTC) is ready (`RAD-PEAP-002`).
- Operator needs PEAP-EAP-TLS, crypto-binding, or session resumption.
- Windows / wpa_supplicant interop is an advertised PASS.
