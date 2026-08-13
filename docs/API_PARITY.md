# REST and MCP Feature-Parity Contract

Status: mandatory  
MCP baseline: 2026-07-28  
Last updated: 2026-08-12

## 1. Objective

REST and MCP are two public adapters over one administrative operation layer. Neither surface is a secondary wrapper around the other. Equivalent operations must have the same validation, authorization, concurrency, side effects, redaction, events, and domain errors.

The UI uses REST. Automation may use REST or MCP. A lab operator must not receive materially different server capabilities merely because a different adapter is used.

The vertical skeleton implements `system.status.get` and `policy.evaluate` on both adapters through the same registry. PR-16a binds the frozen REST surface for every already-implemented handler (status, build, policy.evaluate, session, tokens, events) plus health and `/api/openapi.json`. Remaining REST routes wait for PR-16b. Health probes remain `REST_ONLY_PROTOCOL`. MCP `server/discover` is `MCP_ONLY_PROTOCOL`.

## 2. Source of truth

The repository contains a machine-readable operation registry at `api/operations.yaml`. Typed Go handlers live in `internal/api/operations` and must keep the same IDs. REST and MCP adapters invoke that registry; they do not implement business logic.

Each operation descriptor includes:

```yaml
id: users.create
parity: PARITY_REQUIRED
mutating: true
idempotent: conditional
scopes: [state:write]
request_type: CreateUserRequest
response_type: User
rest:
  method: POST
  path: /api/v1/users
mcp:
  kind: tool
  name: taclab.users.create
audit_event: api.user.created
```

`api/operations.yaml` is the authoritative registry that CI enumerates. Missing REST or MCP bindings fail `make check-registries` even before handlers exist. `events.subscribe` is `PARITY_DIFFERENT_BINDING`: REST `GET /api/v1/events/stream` (SSE bodies) versus MCP `subscriptions/listen` on `taclab://events/recent` (URI-only notify) plus `events.list` for bodies.

### 2.1 Generation and review

1. Add or change the row in this policy document and in `api/operations.yaml` in the same change.
2. Assign a parity disposition. `PARITY_REQUIRED` and `PARITY_DIFFERENT_BINDING` require both REST and MCP bindings.
3. Run `make generate` and commit [docs/generated/api-parity.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/api-parity.md).
4. REST path parameters use `{id}`. The `{name}` spellings in the tables below are aliases for `{id}`.

The registry generates or verifies:

- REST route inventory.
- OpenAPI operation IDs and schemas.
- MCP tool/resource inventory and schemas.
- scope requirements.
- parity tests.
- this operation matrix or a generated successor.

## 3. Parity dispositions

| Disposition | Meaning |
|---|---|
| `PARITY_REQUIRED` | Equivalent capability must be available through REST and MCP in the same release/change |
| `REST_ONLY_PROTOCOL` | HTTP/browser protocol support with no meaningful MCP equivalent |
| `MCP_ONLY_PROTOCOL` | MCP protocol discovery/transport support with no meaningful REST equivalent |
| `PARITY_DIFFERENT_BINDING` | Same capability and operation handler, but transport shape differs, such as SSE versus MCP subscription |
| `EXEMPT_BY_ADR` | Reviewed exception; reason, risk, and future disposition documented |

No unclassified operation is allowed.

## 4. Common operation contract

Every parity-required operation uses the same:

- canonical Go input and output types.
- field normalization.
- validation functions.
- operation handler.
- required scope set.
- principal representation.
- effective-state snapshot semantics.
- expected revision logic.
- idempotency key handling.
- event/audit record.
- secret redaction.
- domain error code.
- pagination and deterministic sort semantics.

Adapters may differ only in protocol representation.

## 5. Common response metadata

Administrative responses should include or make available:

```json
{
  "revision": 42,
  "request_id": "01J...",
  "data": {}
}
```

List responses include:

```json
{
  "revision": 42,
  "items": [],
  "next_cursor": null
}
```

MCP structured content exposes equivalent fields. REST may also use headers such as `ETag` and `X-Request-ID`; those headers do not replace the common structured revision where clients need it.

## 6. Common error taxonomy

| Domain code | REST mapping | MCP mapping |
|---|---|---|
| `invalid_argument` | 400 problem details | tool error/structured error with same code |
| `unauthenticated` | 401 | authorization failure with same code |
| `permission_denied` | 403 | authorization/tool error with same code |
| `not_found` | 404 | structured error |
| `already_exists` | 409 | structured error |
| `conflict` | 409 | structured error |
| `revision_mismatch` | 412 | structured error |
| `rate_limited` | 429 | structured error with retry metadata |
| `unavailable` | 503 | structured error |
| `internal` | 500 | generic tool/protocol error; safe message only |

Internal causes may be logged with a correlation ID but are not exposed as stack traces.

## 7. Concurrency and idempotency parity

### 7.1 Expected revision

- REST mutation: `If-Match: "revision-42"` or the exact generated convention.
- MCP mutation: `expected_revision: 42`.
- Operation handler receives `ExpectedRevision *uint64` regardless of adapter.

### 7.2 Idempotency

- REST uses `Idempotency-Key`.
- MCP mutating tool input uses `idempotency_key` when the operation supports replay protection.
- Both map to the same bounded in-memory idempotency service and response replay rules.
- Idempotency entries disappear on restart with other runtime state unless a future persistence ADR says otherwise.

## 8. Pagination and filtering parity

- Both surfaces use opaque cursors produced by the operation layer.
- Page-size limits are identical.
- Default and maximum sizes are identical.
- Sort order is deterministic and documented.
- Filters use canonical types; adapter aliases are not allowed to change meaning.
- Authorization filtering occurs before cursor creation.

MCP resource convenience views may return a bounded default page and link to a tool for pagination, but the underlying list capability must remain available.

## 9. Operation matrix

Names are proposed stable contracts. A naming change requires migration notes and parity-registry updates.

### 9.1 System and configuration

| Operation ID | Scope | REST | MCP | Disposition |
|---|---|---|---|---|
| `system.status.get` | `state:read` | `GET /api/v1/status` | tool `taclab.system.status.get`; resource `taclab://status` | PARITY_REQUIRED |
| `system.build.get` | `state:read` | `GET /api/v1/build` | tool `taclab.system.build.get`; resource `taclab://build` | PARITY_REQUIRED |
| `config.effective.get` | `state:read` | `GET /api/v1/config/effective` | tool `taclab.config.effective.get`; resource `taclab://config/effective` | PARITY_REQUIRED |
| `config.validate` | `state:write` | `POST /api/v1/config/validate` | tool `taclab.config.validate` | PARITY_REQUIRED |
| `config.reload` | `config:reload` | `POST /api/v1/config/reload` | tool `taclab.config.reload` | PARITY_REQUIRED |
| `config.export` | `config:export` | `GET /api/v1/config/export` | tool `taclab.config.export` | PARITY_REQUIRED |
| `runtime.reset` | `runtime:reset` | `POST /api/v1/runtime/reset` | tool `taclab.runtime.reset` | PARITY_REQUIRED |

`config.validate` accepts a candidate configuration document or a request to validate the mounted source. It never publishes state.

### 9.2 Users

| Operation ID | Scope | REST | MCP | Disposition |
|---|---|---|---|---|
| `users.list` | `state:read` | `GET /api/v1/users` | tool `taclab.users.list`; resource `taclab://users` | PARITY_REQUIRED |
| `users.get` | `state:read` | `GET /api/v1/users/{name}` | tool `taclab.users.get` | PARITY_REQUIRED |
| `users.create` | `state:write` | `POST /api/v1/users` | tool `taclab.users.create` | PARITY_REQUIRED |
| `users.update` | `state:write` | `PATCH /api/v1/users/{name}` | tool `taclab.users.update` | PARITY_REQUIRED |
| `users.delete` | `state:write` | `DELETE /api/v1/users/{name}` | tool `taclab.users.delete` | PARITY_REQUIRED |

User outputs expose credential capability metadata only, such as `ascii_pap_configured` and `challenge_configured`. Secret values and verifier strings are omitted.

### 9.3 Groups and rules

| Operation ID | Scope | REST | MCP | Disposition |
|---|---|---|---|---|
| `groups.list` | `state:read` | `GET /api/v1/groups` | tool `taclab.groups.list`; resource `taclab://groups` | PARITY_REQUIRED |
| `groups.get` | `state:read` | `GET /api/v1/groups/{name}` | tool `taclab.groups.get` | PARITY_REQUIRED |
| `groups.create` | `state:write` | `POST /api/v1/groups` | tool `taclab.groups.create` | PARITY_REQUIRED |
| `groups.update` | `state:write` | `PATCH /api/v1/groups/{name}` | tool `taclab.groups.update` | PARITY_REQUIRED |
| `groups.delete` | `state:write` | `DELETE /api/v1/groups/{name}` | tool `taclab.groups.delete` | PARITY_REQUIRED |

Authorization rules are part of user/group resources for 1.0 unless implementation evidence shows a separate rule resource is necessary. If split, all rule CRUD operations become parity-required.

### 9.4 Network clients

| Operation ID | Scope | REST | MCP | Disposition |
|---|---|---|---|---|
| `clients.list` | `state:read` | `GET /api/v1/clients` | tool `taclab.clients.list`; resource `taclab://clients` | PARITY_REQUIRED |
| `clients.get` | `state:read` | `GET /api/v1/clients/{name}` | tool `taclab.clients.get` | PARITY_REQUIRED |
| `clients.create` | `state:write` | `POST /api/v1/clients` | tool `taclab.clients.create` | PARITY_REQUIRED |
| `clients.update` | `state:write` | `PATCH /api/v1/clients/{name}` | tool `taclab.clients.update` | PARITY_REQUIRED |
| `clients.delete` | `state:write` | `DELETE /api/v1/clients/{name}` | tool `taclab.clients.delete` | PARITY_REQUIRED |

Shared-secret values and certificate private material are write-only references and never appear in outputs. Non-secret shared-secret lifecycle metadata, `current`/`due_soon`/`overdue`/`unknown` status, validation warnings, and reuse-warning client IDs must be equivalent on REST and MCP. A secret fingerprint is never part of either public contract.

### 9.5 API tokens

| Operation ID | Scope | REST | MCP | Disposition |
|---|---|---|---|---|
| `tokens.list` | `tokens:manage` | `GET /api/v1/tokens` | tool `taclab.tokens.list` | PARITY_REQUIRED |
| `tokens.create` | `tokens:manage` | `POST /api/v1/tokens` | tool `taclab.tokens.create` | PARITY_REQUIRED |
| `tokens.revoke` | `tokens:manage` | `DELETE /api/v1/tokens/{id}` | tool `taclab.tokens.revoke` | PARITY_REQUIRED |

The token value appears exactly once in the successful create response on both surfaces. It is never returned by list/get and never embedded in events. Handlers live in `internal/api/operations`; adapters are not required for the operations to function. Lab static bearer (no OAuth PRM) is [ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md).

### 9.6 Diagnostics and test operations

| Operation ID | Scope | REST | MCP | Disposition |
|---|---|---|---|---|
| `policy.evaluate` | `policy:test` | `POST /api/v1/policy/evaluate` | tool `taclab.policy.evaluate` | PARITY_REQUIRED |
| `authentication.test` | `policy:test` | `POST /api/v1/authentication/test` | tool `taclab.authentication.test` | PARITY_REQUIRED |
| `events.list` | `events:read` | `GET /api/v1/events` | tool `taclab.events.list`; resource `taclab://events/recent` | PARITY_REQUIRED |
| `events.subscribe` | `events:read` | `GET /api/v1/events/stream` using SSE | MCP resource/subscription/listen mechanism | PARITY_DIFFERENT_BINDING |

Sensitive event fields require `events:sensitive` in addition to `events:read`. Redaction is performed in the operation layer before adapter encoding.

### 9.7 Protocol-only exceptions

| Capability | Binding | Disposition | Reason |
|---|---|---|---|
| Liveness and readiness probes | REST `/health/live`, `/health/ready` | REST_ONLY_PROTOCOL | Infrastructure HTTP probes, not administrative features |
| OpenAPI document | REST `/api/openapi.json` or YAML | REST_ONLY_PROTOCOL | Describes REST protocol |
| Browser token exchange/session logout | REST endpoints | REST_ONLY_PROTOCOL | Browser cookie/CSRF mechanics. CSRF is required when cookie auth is on. `cookie_secure` follows HTTP TLS. |
| SSE framing/heartbeat | REST | REST_ONLY_PROTOCOL | HTTP event transport mechanics |
| MCP endpoint, discovery, tools/list, resources/list, capability metadata | MCP | MCP_ONLY_PROTOCOL | Required MCP protocol surface |
| MCP tool/list-changed and resource notifications | MCP | MCP_ONLY_PROTOCOL | MCP protocol mechanics; underlying state capability remains parity-covered |

## 10. MCP schema requirements

- Use the official Go SDK's typed tool registration.
- Every tool input and output has a valid JSON Schema.
- Use JSON Schema 2020-12 unless compatibility requires an explicit supported draft.
- Prefer `additionalProperties: false` for closed mutation inputs.
- Tool results provide structured content matching `outputSchema`.
- When required for backwards compatibility, include serialized JSON as text content without adding secret data.
- Tool names are stable, deterministic, unique, and use permitted characters.
- Discovery returns only tools permitted by the caller's scopes.
- The tool list order is deterministic.
- Sensitive fields are never mirrored into MCP HTTP headers.

## 11. REST schema requirements

- OpenAPI 3.1 is checked in or reproducibly generated.
- Every route uses the same operation ID as the canonical registry.
- Write-only secret fields are marked `writeOnly`.
- Read responses omit write-only fields rather than returning null placeholders.
- Schemas set bounds for strings, arrays, page sizes, durations, and rule counts.
- Unknown fields in mutation payloads are rejected.
- API versioning is explicit in the path.
- Breaking schema changes require a versioning/migration decision.

## 12. Parity test suite

### 12.1 Registry completeness

A test enumerates every operation and asserts:

- valid disposition.
- unique operation ID.
- required scope set present.
- REST and MCP binding present for parity-required operations.
- no duplicate route or tool name.
- generated OpenAPI and MCP schemas exist.
- documentation row exists or is generated.

### 12.2 Behavioral equivalence

For each parity-required operation, table-driven tests execute REST and MCP against isolated instances with the same initial state, principal, request, clock, and random seed. Compare:

- domain result.
- effective state.
- revision change.
- emitted event type and redacted fields.
- error code.
- secret omission.
- idempotent replay result.

Wire formatting may differ; domain meaning may not.

### 12.3 Authorization equivalence

For every operation and representative scope set:

- no token.
- invalid token.
- expired token.
- valid token without scope.
- valid token with exact scope.
- valid token with additional scopes.

REST and MCP must permit/deny identically.

### 12.4 Schema equivalence

A generated test compares canonical field definitions against:

- OpenAPI request/response schemas.
- MCP input/output schemas.
- generated TypeScript types.

Differences require an explicit adapter mapping with a parity test.

### 12.5 Redaction equivalence

Seed every secret field with unique canary strings. Exercise all read, export, event, error, and list operations over REST and MCP. Fail if any canary appears outside the one-time token create response or an explicitly permitted write path test.

## 13. Documentation generation

`make generate` writes `docs/generated/api-parity.md` from `api/operations.yaml`. CI runs generation and fails when the working tree changes.

Generated output includes:

- operation ID.
- description.
- scopes.
- REST method/path.
- MCP tool/resource.
- input/output schema links.
- mutating/idempotency classification.
- parity disposition.
- implementation/test status.

This hand-authored file remains the policy contract; the generated file becomes the live implementation inventory.

## 14. Change checklist

For any new or changed administrative feature:

- [ ] Add or update the canonical operation.
- [ ] Assign parity disposition.
- [ ] Add or update common request/response types.
- [ ] Add validation and common handler tests.
- [ ] Add REST binding and contract tests.
- [ ] Add MCP binding and contract tests.
- [ ] Add behavioral parity test.
- [ ] Add scope matrix test.
- [ ] Add secret-redaction test.
- [ ] Update OpenAPI and generated TypeScript client.
- [ ] Update MCP schemas and discovery snapshots.
- [ ] Update generated parity documentation.
- [ ] Update UI when the feature is operator-facing.
- [ ] Update benchmark when operation affects a hot path or large list.
