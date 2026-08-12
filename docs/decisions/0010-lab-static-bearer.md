# ADR 0010: Lab Static Bearer vs MCP OAuth Protected Resource Metadata

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P9.3, P9.4, P11  
Disposition: `EXEMPT_BY_ADR`

## Context

MCP 2026-07-28 HTTP authorization is optional. When HTTP authorization is used, the specification **SHOULD** advertise OAuth 2.0 Protected Resource Metadata (PRM) at `.well-known/oauth-protected-resource` so standard clients can discover how to obtain tokens.

TacLab 1.0 is a disposable single-replica lab appliance. Administrative access uses the same scoped static bearer tokens on REST and MCP. Bootstrap tokens are file-referenced; runtime tokens are generated with ≥256 bits of entropy and stored only as SHA-256 digests. The UI exchanges a bearer for an HttpOnly session cookie with mandatory CSRF. There is no external identity provider in the 1.0 product.

Implementing OAuth PRM, dynamic client registration, and a token endpoint would imply a capability the appliance does not have. Advertising PRM without implementing OAuth would be more harmful than documenting the exemption.

## Decision

1. **Lab static bearer** (`api.mode: lab_static_bearer`) is the 1.0 authorization mechanism for REST and MCP. The same verifier, digest index, and exact-match scope matrix apply to both adapters.
2. This is **`EXEMPT_BY_ADR`** relative to the MCP HTTP-authorization OAuth PRM **SHOULD**. TacLab 1.0 does **not** implement `.well-known/oauth-protected-resource`, authorization servers, or OAuth token issuance.
3. Unauthenticated HTTP requests return 401. Adapters may send `WWW-Authenticate: Bearer realm="taclab"` as a courtesy. That header is not an OAuth discovery document.
4. Standard MCP clients that require OAuth PRM will not complete discovery. Operator documentation must state this interop limit. Do not pretend OAuth works.
5. Browser sessions remain `REST_ONLY_PROTOCOL`. `cookie_secure` follows `listeners.http.tls.enabled` unless explicitly overridden. CSRF is required on cookie-authenticated mutations even when the lab serves HTTP (`cookie_secure: false`).
6. A future standards-oriented OAuth mode may be added behind the same principal and scope interface. That change requires a new ADR and must not silently replace lab static bearer.

## Alternatives considered

### Implement OAuth PRM in 1.0

Rejected. There is no authorization server, no client registration, and no refresh-token lifecycle in the lab product. A stub PRM document would fail closed for honest clients and confuse operators.

### No HTTP authorization

Rejected. The admin API mutates users, groups, clients, and tokens. Unauthenticated admin access is not acceptable even in a lab.

### Distinct REST and MCP credentials

Rejected. Parity requires one verifier and one scope matrix.

## Consequences

### Positive

- One token model for REST, MCP, and the UI session exchange.
- No fake OAuth surface.
- Scope checks stay in the operation registry.

### Negative

- MCP clients that insist on OAuth PRM cannot authorize against TacLab 1.0.
- Operators must distribute bootstrap token files out of band.

### Mitigations

- Document the exemption in this ADR, operator docs, and `WWW-Authenticate` as a realm only.
- Keep the principal/scope interface so an OAuth mode can be added later without rewriting handlers.
- Secret canaries forbid bearer values after the one-time create response.

## Compatibility impact

- MCP clients must send `Authorization: Bearer <token>` with a TacLab-issued token.
- No `.well-known/oauth-protected-resource` route is served (404 or unconfigured).
- UI must use session cookies, not `localStorage` / `sessionStorage` for bearers.

## Migration

None. 1.0 ships only lab static bearer. A later OAuth mode is additive.

## Test impact

- Correct, malformed, unknown, expired, and revoked bearers share `unauthenticated`.
- Exact required scope, missing scope, and extra unrelated scopes.
- Bootstrap file load fail-closed.
- Cookie mutation without CSRF is denied.
- `cookie_secure` follows TLS.
- Canaries scan create-once vs list/errors.

## Documentation impact

`docs/decisions/0010-lab-static-bearer.md` is the exemption SoT. Link from the root README, `docs/REFERENCES.md`, `docs/ARCHITECTURE.md`, and `docs/TASKS.md` P9.3/P11.

## Revisit conditions

- A required MCP client cannot operate without PRM.
- TacLab grows an external identity integration.
- MCP makes HTTP authorization and PRM mandatory for this deployment class.
