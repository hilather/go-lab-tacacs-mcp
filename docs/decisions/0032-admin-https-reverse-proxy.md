# ADR 0032: Admin HTTPS terminates at a reverse proxy

Status: accepted

## Context

The HTTP admin listener accepts `tls.enabled` but has no certificate or private-key configuration and serves plaintext. Accepting `true` therefore misrepresents the security boundary. The reference lab uses HTTP; hosted MCP already documents HTTPS termination at a proxy.

## Decision

Reject `listeners.http.tls.enabled: true` during configuration validation for both schema versions, including candidate validation/reload. Defend the same boundary at HTTP startup. Retain the false-valued field for compatibility. HTTPS terminates at an operator-managed reverse proxy; set `api.ui_session.cookie_secure: true` explicitly for HTTPS browser access.

## Alternatives

Implementing native admin TLS would require certificate lifecycle, key loading, configuration schema, and deployment contracts. Silently accepting the flag preserves an unsafe false assurance. Neither is suitable for this corrective slice.

## Consequences and compatibility

Previously accepted configurations with `tls.enabled: true` now fail closed before binding. HTTP-only configurations remain valid. No public administrative operation or parity disposition changes. TACACS TLS and RadSec remain independent.

## Migration

Set `listeners.http.tls.enabled: false`, configure HTTPS on a reverse proxy, and explicitly enable secure browser cookies. Preserve the authorization and MCP protocol headers and configure stream buffering/timeouts as described in `docs/MCP.md`. Restrict the plaintext upstream listener to the trusted proxy network.

## Test and documentation impact

Configuration regressions cover both schema versions. Startup rejects the flag before bootstrap work. Update the canonical design and configuration guidance to describe the actual TLS boundary. No protocol codec or hot request path changes are involved.
