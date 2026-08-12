# ADR 0005: Session Ticket Lifetime, Resumption, and Linkability

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P8.4  
Related conformance rows: T98-RES-001, T98-RES-002, T98-RES-005, T98-RES-006, T98-RES-007, T98-RES-008

## Context

RFC 9887 SHOULD make ticket lifetime configurable, including zero, and SHOULD review ticket reuse/linkability. Go 1.24.5 `crypto/tls` defines:

```go
const maxSessionTicketLifetime = 7 * 24 * time.Hour
```

Every ticket the server sends uses that lifetime. There is no hook to advertise a shorter or longer value. Ticket encryption keys rotate on a 7-day `ticketKeyLifetime`. `VerifyPeerCertificate` is skipped on resume.

## Decision

1. `session_resumption.enabled: false` or `ticket_lifetime: 0` sets `SessionTicketsDisabled`.
2. The only accepted non-zero `ticket_lifetime` is **168h**, equal to `maxSessionTicketLifetime`. Any other positive value is a configuration error. The previous 24h example is rejected, not silently stretched to 7 days.
3. Default `ticket_lifetime` is 168h.
4. Every connection, including resumed ones, runs `VerifyConnection`: path re-check when `VerifiedChains` is empty, configured CRL, and client-match. `recheck_client_revocation: true` is the only 1.0 behavior; `false` is a configuration error (not silently ignored).
5. Ticket reuse/linkability: TacLab does not add extra tracking mitigations beyond Go’s rotating ticket keys. Clients that resume are linkable for the ticket lifetime. This SHOULD is dispositioned here.
6. 0-RTT remains MUST NOT: `GetConfigForClient` rejects ClientHello extension 42 (`early_data`). `reject_early_data: false` is a configuration error.

## Alternatives considered

### Treat any positive lifetime as “enabled” and use 7 days

Rejected. That silently ignores the configured value.

### Disable resumption always

Rejected. Resumption is useful for handshake benches and RFC SHOULD T98-RES-001. Operators can set lifetime 0.

## Consequences

### Positive

- Configured lifetime is either honored exactly or rejected.
- Revocation and identity still apply on resume.

### Negative

- Labs cannot request a 1-hour ticket.
- Go may still accept a presented ticket until its own 7-day cap.

## Compatibility impact

Existing YAML with `ticket_lifetime: 24h` must be changed to `0s` or `168h`.

## Migration

Update `configs/lab.example.yaml` and operator docs to 168h. Validation error text names this ADR.

## Test impact

- Config rejects 24h and `recheck_client_revocation: false`.
- `ticket_lifetime: 0` and `enabled: false` do not resume.
- 168h resumes; overwriting the CRL with the client serial fails the next resume.

## Documentation impact

This ADR is the SoT for T98-RES-002/005/007. The enforced cap is `config.TLSTicketLifetimeEnforced`.

## Revisit conditions

- Go exposes a ticket-lifetime hook that can honor values other than 7 days.
- A lab profile requires single-use tickets.
