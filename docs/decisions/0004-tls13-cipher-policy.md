# ADR 0004: TLS 1.3 Cipher-Policy Configurability

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P8.2  
Related conformance rows: T98-CERT-007, T98-CERT-008, T98-TLS-011  
Disposition: DISPOSITIONED_SHOULD

## Context

RFC 9887 SHOULD allow a safe, configurable TLS 1.3 cipher policy. Go 1.24.5 `tls.Config.CipherSuites` applies only to TLS 1.0–1.2. TLS 1.3 suites are selected internally from:

- `TLS_AES_128_GCM_SHA256` (mandatory)
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

There is no supported way to honor an operator-supplied TLS 1.3 suite list.

## Decision

1. The secure listener sets `MinVersion = MaxVersion = VersionTLS13` and leaves `CipherSuites` unset so Go offers its TLS 1.3 mandatory set.
2. YAML `listeners.secure_tacacs.tls.cipher_suites` is **not** a schema key. Supplying it is `CONFIG_UNKNOWN_FIELD`.
3. Do not accept a list and then negotiate a different suite.

## Alternatives considered

### Restrict suites via undocumented internals

Rejected. Fragile across Go patch releases.

### Accept YAML and ignore unknown suites

Rejected. Silent approximation is prohibited.

## Consequences

### Positive

- Handshake always uses a Go-supported TLS 1.3 AEAD suite (BCP 195).
- Operators cannot claim a cipher the stack cannot enforce.

### Negative

- Labs cannot pin a single TLS 1.3 suite for interop experiments.

## Compatibility impact

Clients must offer at least one suite from Go’s TLS 1.3 set.

## Migration

None. A future Go API for TLS 1.3 suite policy requires a new ADR and a versioned YAML key.

## Test impact

- Unknown-field fixture `cipher_suites.yaml`.
- Handshake asserts the negotiated suite is one of the three TLS 1.3 suites above.

## Documentation impact

This ADR is the disposition for T98-CERT-008. T98-CERT-007 remains a MUST implemented by the stack default.

## Revisit conditions

- `crypto/tls` exposes a supported TLS 1.3 suite list.
- FIPS-only mode needs a documented subset.
