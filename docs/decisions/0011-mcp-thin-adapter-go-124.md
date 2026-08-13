# ADR 0011: Thin MCP JSON-RPC Adapter on Go 1.24.5

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P11, PR-17  
Disposition: temporary compatibility layer

## Context

Key Decision 9 and the canonical design require MCP 2026-07-28 Streamable HTTP
(`POST /mcp` only, `server/discover`, per-request `_meta`, `resultType`,
CacheableResult, `Mcp-Method` / `Mcp-Name`, `subscriptions/listen` as a URI
notify channel) using the official Go SDK.

`github.com/modelcontextprotocol/go-sdk v1.7.0` is the first release that
implements protocol `2026-07-28`. Its module requires **Go 1.25.0**. This
repository is pinned to **Go 1.24.5**. Raising the Go pin is out of scope for
PR-17.

Shipping a compile-time SDK import would break `go test` on the pinned
toolchain. Pretending the SDK is in use while vendoring nothing would fail
honest documentation.

## Decision

1. Implement MCP 2026-07-28 as a **thin JSON-RPC Streamable HTTP adapter** in
   `internal/api/mcp`. It calls `internal/api/operations` and never the REST
   adapter.
2. Record `github.com/modelcontextprotocol/go-sdk v1.7.0` as the **intended**
   SDK baseline in `go` toolchain docs. It is **not** a compile-time
   dependency while the Go pin is 1.24.5.
3. The adapter must still satisfy the 2026-07-28 checklist in the canonical
   design: `POST /mcp` only, `server/discover`, `_meta`, `resultType`,
   CacheableResult `ttlMs: 0` / `cacheScope: "private"`, `404`/`-32601`,
   Origin policy, `Mcp-Method` / `Mcp-Name`, no event-body firehose.
4. Lab static bearer remains [ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)
   (`EXEMPT_BY_ADR`). MCP uses the same `auth.Service` snapshot verifier as REST.
5. Adopt the official SDK in a later change when the Go pin is 1.25+ (or the
   SDK publishes a 1.24-compatible 2026-07-28 release). That change needs
   transport-contract re-tests, not a new operation registry.

## Alternatives considered

### Raise the Go pin to 1.25 in PR-17

Rejected. The toolchain pin is a P0 contract. Bumping Go here would mix a
platform change with the MCP adapter.

### Depend on the SDK anyway

Rejected. `go test` cannot compile a `go 1.25.0` module on Go 1.24.5.

### Leave MCP as the three-tool skeleton

Rejected. PR-17 requires operation parity on the MCP surface.

## Consequences

### Positive

- MCP 2026-07-28 behavior is testable on the pinned toolchain.
- REST/MCP still share one registry, scopes, and types.
- The gap versus the official SDK is explicit.

### Negative

- JSON-RPC framing is maintained in-tree until the SDK can be imported.
- Clients that require SDK-only extensions (MRTR elicitation, OAuth PRM) are
  still out of 1.0 scope.

### Mitigations

- Keep the adapter thin: decode, authorize, invoke, encode.
- Contract tests cover headers, `_meta`, Origin, 404/`-32601`, CacheableResult,
  and URI-only listen.
- Revisit when Go 1.25 is the pin.

## Compatibility impact

- MCP clients must send `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`,
  `params._meta` (`protocolVersion` + `clientCapabilities`), and `Mcp-Name`
  for `tools/call`, `resources/read`, and `prompts/get`.
- GET/DELETE `/mcp` return 405. `Mcp-Session-Id` and `Last-Event-ID` are ignored.
- `subscriptions/listen` notifications carry URI + `subscriptionId` only.

## Migration

None for operators. A later SDK swap should keep the same `/mcp` path, tool
names, resource URIs, and listen binding.

## Test impact

- Header/`_meta` mismatch → `400` / `-32020`.
- Unsupported version → `400` / `-32022` with `supported: ["2026-07-28"]`.
- Unknown RPC → `404` / `-32601`.
- Listen write-timeout survival and no event-body leak.
- Scope-filtered `tools/list` / `resources/list`.

## Documentation impact

Link from `docs/ARCHITECTURE.md`, `docs/DESIGN.md` §16.1, `docs/REFERENCES.md`,
`docs/API_PARITY.md`, `docs/TASKS.md` P11, and the root README.

## Revisit conditions

- The Go pin is 1.25 or later.
- The official SDK publishes a 2026-07-28 release that builds on Go 1.24.5.
