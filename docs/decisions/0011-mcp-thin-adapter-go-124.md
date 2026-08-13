# ADR 0011: Official MCP Go SDK (was: thin adapter on Go 1.24.5)

Status: Adopted  
Date: 2026-08-12  
Amended: 2026-08-13 — Go pin 1.25.0; `github.com/modelcontextprotocol/go-sdk v1.7.0` is a compile-time dependency.  
Decision owners: TacLab maintainers  
Related tasks: P11, PR-17  
Disposition: current MCP transport

## Context

Key Decision 9 and the canonical design require MCP 2026-07-28 Streamable HTTP
(`POST /mcp` only, `server/discover`, per-request `_meta`, `resultType`,
CacheableResult, `Mcp-Method` / `Mcp-Name`, `subscriptions/listen` as a URI
notify channel) using the official Go SDK.

`github.com/modelcontextprotocol/go-sdk v1.7.0` is the first release that
implements protocol `2026-07-28`. Its module requires **Go 1.25.0**. PR-17
shipped while this repo was pinned to Go 1.24.5, so 1.0 first used a thin
in-tree JSON-RPC adapter. The Go pin is now 1.25.12 (`go 1.25.0` in
`go.mod`), which is the revisit condition from the original decision.

## Decision

1. Import `github.com/modelcontextprotocol/go-sdk v1.7.0`. Framing,
   `server/discover`, tools, and resources go through
   `StreamableHTTPHandler` with `Stateless = true` and `JSONResponse = true`.
2. Keep lab bearer, origin policy, exclusive `MCP-Protocol-Version:
   2026-07-28`, and URI-only `subscriptions/listen` in `internal/api/mcp`.
   Listen still enforces per-request `_meta` (`protocolVersion` +
   `clientCapabilities`) before opening the SSE stream.
3. Tools and resources still call `internal/api/operations` and never the
   REST adapter. All implemented tools are registered; `tools/list` /
   `resources/list` are scope-filtered in receiving middleware so a missing
   scope is `permission_denied`, not an unknown tool.
4. Lab static bearer remains [ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)
   (`EXEMPT_BY_ADR`). MCP uses the same `auth.Service` snapshot verifier as REST.

## Residuals clients can observe

- List/read `cacheScope` is forced to `"private"` in receiving middleware
  (SDK default is `"public"`). Discover keeps `"public"`.
- Discover `supportedVersions` is filtered to `["2026-07-28"]`. The SDK
  default list includes legacy versions that the header gate rejects.
- `Mcp-Name` is ASCII only; the SDK does not decode `=?base64?...?=`.
- Domain not-found on a registered tool is JSON-RPC `-32000`. The SDK
  rewrites any `WireError` with `-32601` as "method not found".
- Unknown `prompts/get` is SDK `-32602`, not `404`/`-32601`.
- Official MRTR elicitation and OAuth PRM remain out of 1.0.

## Original decision (2026-08-12)

PR-17 implemented a thin in-tree adapter and recorded the SDK as intended
but not imported, because compiling `go-sdk v1.7.0` on Go 1.24.5 would
break `go test`. Raising the Go pin in that PR was rejected as mixed
scope. That layout is superseded by the Decision above.

## Alternatives considered

### Stay on the thin adapter after Go 1.25

Rejected. The original revisit condition is met. Framing belongs in the
official SDK; the adapter should stay thin around lab policy.

### Depend on the SDK in PR-17 on Go 1.24.5

Rejected at the time. `go test` cannot compile a `go 1.25.0` module on
Go 1.24.5.

### Raise the Go pin to 1.25 in PR-17

Rejected at the time. The toolchain pin was a P0 contract separate from
the MCP adapter.

## Consequences

### Positive

- Streamable HTTP framing and 2026-07-28 discover/tools/resources come
  from the official SDK.
- REST/MCP still share one registry, scopes, and types.
- Residuals versus the SDK defaults are listed above.

### Negative

- Listen remains in-tree (URI-only, write-timeout survival).
- Clients that require MRTR elicitation or OAuth PRM are still out of 1.0.

### Mitigations

- Contract tests cover headers, `_meta` (including listen), Origin,
  404/`-32601`, exclusive `supportedVersions`, CacheableResult, official
  SDK client connect, and URI-only listen.
- Domain errors avoid `-32601` so the SDK does not rewrite them.

## Compatibility impact

- MCP clients must send `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`,
  `params._meta` (`protocolVersion` + `clientCapabilities`), and ASCII
  `Mcp-Name` for `tools/call`, `resources/read`, and `prompts/get`.
- GET/DELETE `/mcp` return 405. `Mcp-Session-Id` and `Last-Event-ID` are ignored.
- `subscriptions/listen` notifications carry URI + `subscriptionId` only.

## Migration

None for operators. `/mcp` path, tool names, resource URIs, and listen
binding are unchanged.

## Test impact

- Header/`_meta` mismatch → `400` / `-32020` (SDK methods and listen).
- Unsupported version → `400` / `-32022` with `supported: ["2026-07-28"]`.
- Unknown RPC → `404` / `-32601`.
- Listen write-timeout survival and no event-body leak.
- Scope-filtered `tools/list` / `resources/list`.
- Official SDK client can `Connect` / `ListTools` / `CallTool`.

## Documentation impact

Link from `docs/ARCHITECTURE.md`, `docs/DESIGN.md` §16.1, `docs/REFERENCES.md`,
`docs/API_PARITY.md`, `docs/TASKS.md` P11, and the root README.

## Revisit conditions

- Official MRTR elicitation or OAuth PRM is in scope.
- The SDK learns URI-only listen with write-timeout survival.
- The SDK stops rewriting application `-32601` errors.
