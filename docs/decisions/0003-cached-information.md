# ADR 0003: RFC 7924 Cached Information Extension

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P8.2  
Related conformance rows: T98-CERT-010  
Disposition: DISPOSITIONED_SHOULD

## Context

RFC 9887 says implementations SHOULD support the TLS Cached Information Extension (RFC 7924) so peers can omit previously seen certificates. Go 1.24.5 `crypto/tls` has no hook to advertise, parse, or honor Cached Information. Ordinary certificate-chain and session-resumption support is not RFC 7924.

## Decision

TacLab 1.0 does **not** implement RFC 7924.

1. The secure listener presents the configured certificate chain on every full handshake.
2. Session resumption (when enabled) is the only certificate-omission path, via TLS 1.3 tickets. That is not Cached Information.
3. Do not mark T98-CERT-010 PASS from resumption tests.

## Alternatives considered

### Third-party TLS stack

Rejected. The product TLS contract is pinned `crypto/tls`. A second stack would split mTLS, CRL, and 0-RTT policy.

### Advertise the extension and ignore it

Rejected. Silent approximation of a SHOULD is prohibited.

## Consequences

### Positive

- Handshake behavior matches the documented Go stack.
- Operators cannot configure a feature the process cannot enforce.

### Negative

- Bandwidth for full certificate chains on every full handshake.
- Interop with clients that require Cached Information will fail that optional path.

## Compatibility impact

None. Clients that do not send Cached Information are unaffected.

## Migration

None. If a future Go release exposes a hook, file a new ADR before advertising support.

## Test impact

- Config rejects unknown `cached_information` YAML (unknown field).
- Handshake matrix does not claim RFC 7924.

## Documentation impact

This ADR is the disposition for T98-CERT-010. `docs/REFERENCES.md` records the missing hook.

## Revisit conditions

- Pinned `crypto/tls` grows a Cached Information API.
- A required interop peer cannot complete a handshake without it.
