# ADR 0006: External TLS PSK and Raw Public Keys

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P8.5  
Related conformance rows: T98-OPT-001 through T98-OPT-005  
Disposition: DEFERRED_MAY

## Context

RFC 9887 MAY support external TLS 1.3 PSKs and raw public keys. TacLab 1.0 requires certificate-based mTLS (`require_and_verify_certificate`). A PSK or RPK path that weakens or bypasses that baseline is out of scope.

`credentials.PurposeTLSPSK` exists so a later isolated adapter can use a typed holder. It is not accepted as a configured authentication method in 1.0.

## Decision

1. External PSK is **DEFERRED_MAY**. Do not advertise it in config, UI, or status.
2. Raw public keys are **DEFERRED_MAY**.
3. Typed secret purpose `tls_psk` remains reserved. Cross-purpose assignment of a legacy shared secret as a PSK is still a validation error if a PSK key ever appears.
4. Conditional rows T98-OPT-002/003/004 stay unstarted until an implementation ADR lands.

## Alternatives considered

### Ship PSK in 1.0 behind a flag

Rejected. Isolation, RFC 9257 guidance, and tests would expand this PR past the TLS server contract.

## Consequences

### Positive

- mTLS remains the only secure-TACACS authentication method.
- A later PSK adapter has a reserved secret type.

### Negative

- Peers that only speak external PSK cannot authenticate.

## Compatibility impact

None. No YAML key is added.

## Migration

A future ADR must add isolated config, tests, and must not disable `RequireAndVerifyClientCert` in the baseline profile.

## Test impact

- Unknown PSK/RPK YAML keys fail as unknown fields.
- Secret-purpose tests keep `tls_psk` distinct from `legacy_shared_secret`.

## Documentation impact

This ADR is the 1.0 disposition for T98-OPT-001 and T98-OPT-005.

## Revisit conditions

- A required interop peer needs external PSK or RPK.
- A spike proves the adapter cannot disable mTLS.
