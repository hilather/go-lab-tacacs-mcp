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

PEAP review hardening (`RAD-REV-002`) limits each TLS flight and each input/output pipe to 64 KiB. Fragmented flights must declare their total length in the first fragment; repeated length flags, mismatched totals, unsupported versions and overflow fail closed. Continuations must match the challenged EAP identifier. Terminal failures, idle TTL expiry, runtime reset and shutdown close the tunnel. Successful handshakes clear the handshake deadline; inner reads retain their bounded per-read timeout.

The PEAP registry reuses `challenge_entries`, `challenge_bytes` and `challenge_ttl` as a **separate** reservation budget, rather than sharing Challenge byte accounting. Each tunnel reserves four 64 KiB buffers (input, output, reassembly and queued output); the cap is the smaller of the entry limit and byte budget divided by 256 KiB. The default 1 MiB therefore permits four concurrent PEAP tunnels. The cap never drops below one tunnel: `challenge_bytes` values from the 64 KiB minimum up to 256 KiB admit exactly one tunnel, so PEAP buffer memory can exceed a sub-256 KiB `challenge_bytes` by up to one 256 KiB reservation. Output queued for fragmentation comes from the bounded TLS output pipe. Admission never evicts a live tunnel. Complete tunneled EAP remains deferred.

Minimum-budget decision (`RAD-REV-002` follow-up): the earlier `min(entries, bytes/256 KiB)` cap was zero for legal budgets below 256 KiB, so every PEAP Start built a tunnel and then sent Access-Reject without State. Alternatives considered: (a) reject `challenge_bytes` < 256 KiB at startup when a PEAP identity exists, or (b) floor the tunnel cap at one. We chose (b). Option (a) would turn configurations that load today, and that size the Challenge State store correctly, into fatal load errors for a PEAP-only budget. Option (b) keeps those configs working, and the overrun is a fixed 256 KiB that does not grow. Compatibility: no schema or default change. Budgets of 256 KiB and above behave exactly as before. Tests: `TestPEAPRegistryAdmitsOneTunnelBelowReservation`, `TestEAPPEAPStartWithMinimumChallengeBytes` and `TestAttachPEAPMinimumChallengeBytesAdmitsOneTunnel`.

TLS-in-EAP reserved flag bits (0x18, the R bits of RFC 5216 section 3.1 that remain after PEAP's version field) are ignored on receipt and never sent; only an unsupported version fails closed (`TestParseIgnoresReservedFlagBits`, fuzz seeds with reserved bits set).

`RAD-REV-004` preserves decision item 5 for the inner-method increment: MSCHAPv2 credential verification is separate from the outer `eap` policy classification. Sanitized policy replies survive until the signed final Access-Accept; duplicate order is preserved and retained attributes count against Challenge storage.
