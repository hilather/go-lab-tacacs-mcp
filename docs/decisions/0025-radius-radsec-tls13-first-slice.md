# ADR 0025: RadSec First Slice (RADIUS/TLS 1.3 TCP 2083)

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-005  
Related conformance rows: PRJ-SEC-002, PRJ-RUN-002  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

[ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md) ships RADIUS/UDP as a controlled-network profile and requires a later ADR for secure transport. RFC 6614 RadSec is RADIUS over TLS. RFC 6613 defines length-prefixed TCP framing. RFC 7360 DTLS and RADIUS/1.1 are larger than a first slice.

A thin `tls.Listen` wrap of the UDP datagram handler would be a false claim.

The tree currently allows at most one RADIUS UDP endpoint per client. RadSec adds a second carrier.

## Decision

1. The secure-transport first slice is **RadSec: RADIUS/TLS 1.3 on TCP 2083**. Default `enabled: false`.
2. It is a **stream of length-prefixed RADIUS packets** (RFC 6613 §2.6) inside TLS 1.3 (RFC 6614, cipher policy [ADR 0004](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0004-tls13-cipher-policy.md), tickets [ADR 0005](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0005-ticket-lifetime.md)). Do not describe RadSec as “UDP plus TLS.”
3. **DTLS (RFC 7360) and RADIUS/1.1 are deferred.** Cleartext RADIUS/TCP is not offered.
4. A client may have **at most one RADIUS endpoint per carrier**: one `radius/udp` and one `radius/tls`. Access/accounting indexes are per `(role, carrier)`.
5. **DAC CoA stays UDP** ([ADR 0024](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0024-radius-coa-disconnect.md)): even when Accounting-Start arrives on RadSec, originate uses the client's UDP RADIUS endpoint secret and dest knobs. A TLS-only RADIUS client cannot originate CoA.
6. Shared secret remains **required** for User-Password hide, authenticators, and Message-Authenticator. Do not default the informal well-known secret `radsec`. Do not special-case that string.
7. Client match after TLS handshake uses a cert index (`address_and_certificate` or `certificate_only`). `certificate_only` requires a TACACS TLS **or** RADIUS TLS endpoint.
8. Challenge bind on RadSec is `tls_cert` (peer certificate fingerprint), not TCP peer IP ([ADR 0021](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0021-radius-access-challenge-state-gate.md)).
9. `internal/radius/tls` must not import `internal/radius/udp` or `internal/tacacs/tls`. Shared TLS policy lives in `internal/config` (`SecureTLS`). Shared tables live in `internal/radius/runtime`.
10. Keep **2083** off the public internet unless the operator intentionally publishes it behind the same posture as TACACS 300.
11. `system.build.get` may add `"RFC 6614"` to RADIUS `standards` only after RadSec tests pass. **`conformance_status` stays `partial`.**

## Alternatives considered

### Require RadSec before any more UDP features

Rejected. Challenge/EAP/MS-CHAP/CoA are useful on the existing UDP lab profile.

### Thin TLS wrap of the UDP handler

Rejected. RFC 6614 is TCP + length-prefixed packets.

### Offer cleartext RADIUS/TCP

Rejected. Adds a cleartext stream with no security win over UDP.

### Adopt default secret `radsec`

Rejected. Operators who want that value put it in a secret file and still meet `security.radius_shared_secrets`.

## Consequences

### Positive

- Labs can speak RadSec without claiming DTLS or RADIUS/1.1.
- UDP and TLS secrets cannot be mixed for CoA.

### Negative

- Two RADIUS endpoints per client increase match/compile complexity.
- TLS-only clients cannot originate CoA.

## Compatibility impact

No RadSec listener ships in this documentation change. Existing UDP match and `at most one RADIUS UDP endpoint` stay until the implementing PR replaces helpers with per-carrier selection.

## Migration

Operators add `listeners.radius.radsec` and a `transport: tls` endpoint after the implementing PR. Old binaries reject those unknown v2 keys. Comment them out before downgrade.

## Test impact

- Independent `testclient` TLS client on a live listener.
- Length-prefix framing; no stitching two packets beyond Length.
- DAC still resolves UDP secret when Start was recorded on TLS.
- Import test: `radius/tls` -/-> `radius/udp`.
- Shared-codec loopback is not sufficient.

## Documentation impact

Do not claim “secure RADIUS” as an upgrade of UDP. [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) §8 keeps RadSec still-deferred until the implementing PR. DTLS/1.1 stay deferred under this ADR's Revisit.

## Revisit conditions

- An operator needs RADIUS/DTLS (RFC 7360).
- An operator needs RADIUS/1.1 hop-by-hop ALPN / changed authenticator.
- BlastRADIUS or RADEXT guidance requires a stricter default than UDP+optional RadSec.
