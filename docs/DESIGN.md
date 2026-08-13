# TacLab Detailed Design

> Execution source of truth for this repository is [CANONICAL_DESIGN.md](CANONICAL_DESIGN.md). This packet file is historical intent; the canonical design wins on conflict.

Status: implementation baseline  
Target release: 1.0 lab appliance  
Last updated: 2026-08-12

## 1. Executive summary

TacLab is a fully functional TACACS+ server for repeatable network-device lab scenarios. It provides complete current core TACACS+ authentication, authorization, and accounting behavior; legacy and TLS 1.3 transports; a reactive browser UI; and equivalent REST and MCP administrative capabilities.

The product is intentionally light in user and group administration while strict in protocol behavior. Users and groups are simple, flat resources. Authorization rules are deterministic and explainable. The configured lab baseline is immutable. Runtime-created or runtime-overridden objects live only in memory and vanish at restart.

The implementation uses:

- Go for the server, protocol engine, application services, REST, MCP, and embedded asset hosting.
- React and TypeScript for the web UI.
- YAML for the versioned baseline configuration.
- the official MCP Go SDK for MCP.
- OCI/Docker images and Docker Compose as the reference deployment.

## 2. Problem statement

Lab teams need to reproduce TACACS+ behaviors without deploying a full enterprise identity or network-management stack. Existing tools often create one or more of these problems:

- Protocol support is incomplete or only covers ASCII login.
- Command authorization behavior is difficult to inspect.
- Configuration changes require process restarts or rewriting generated configuration.
- Administrative APIs expose a different feature set from the UI.
- Runtime lab changes contaminate the reusable baseline.
- Deployment requires multiple services, a database, or privileged host setup.

TacLab solves these by providing one deterministic, disposable appliance with complete AAA behavior, explainable policy decisions, and consistent management surfaces.

## 3. Goals

### 3.1 Protocol goals

- Implement all current core RFC 8907 server-side authentication flows.
- Implement authorization request/reply semantics, standard AV-pair dictionaries, command and session authorization, and vendor AV-pair extensibility.
- Implement all valid accounting forms and reject invalid flag combinations correctly.
- Implement single-connect multiplexing and non-single-connect lifecycle behavior.
- Implement per-client shared-secret legacy transport correctly while rejecting cleartext packet bodies.
- Implement all RFC 9887 mandatory server behavior for TACACS+ over TLS 1.3.
- Provide independent conformance fixtures and cross-implementation interoperability tests.

### 3.2 Lab goals

- Start from one configuration file plus secret files.
- Restore the exact baseline on restart.
- Allow temporary users, groups, clients, policies, and API tokens to be created while running.
- Support both legacy devices and secure TACACS+ devices in the same lab appliance using separate listeners.
- Provide live accounting and decision visibility.
- Make policy decisions reproducible and explainable.
- Run with a single Docker Compose command.

### 3.3 API and UI goals

- Keep REST and MCP administrative behavior in parity.
- Provide typed, versioned contracts.
- Provide a reactive and accessible UI without duplicating backend business logic.
- Make configured versus runtime state obvious.
- Prevent secrets from being read back after initial creation.
- Support config validation, reload, export, and runtime reset.

### 3.4 Engineering goals

- Every defect gets a regression test.
- Every protocol parser and state machine gets fuzz coverage.
- Hot paths have stable benchmarks and regression thresholds.
- Documentation and generated contracts remain current in every change.
- Concurrency behavior is validated using the Go race detector.
- Memory use remains bounded by configuration.

## 4. Non-goals for 1.0

- Enterprise-scale identity lifecycle workflows.
- Nested groups, role hierarchies, approval workflows, or delegated administration.
- High-availability multi-replica runtime state.
- A required external database.
- RADIUS support.
- Acting as an LDAP, SAML, OIDC, or Kerberos identity provider.
- Rewriting the baseline YAML in place.
- Treating deprecated TACACS+ redirection, SENDPASS, or insecure SEND authentication as normal supported features.
- Kubernetes as the primary deployment mechanism.

Optional RFC 9887 external PSK and raw-public-key authentication are tracked explicitly in the conformance matrix. Certificate-based mutual TLS is mandatory for 1.0. Optional TLS mechanisms may be added only without weakening certificate behavior.

## 5. Normative baselines

The implementation is pinned to:

- RFC 8907 for TACACS+.
- RFC 9887 for TACACS+ over TLS 1.3.
- MCP specification 2026-07-28 for the initial MCP implementation.
- the compatible official MCP Go SDK release pinned in `go.mod`.
- OpenAPI 3.1 for REST description.
- JSON Schema 2020-12 for operation schemas unless the pinned MCP SDK requires a compatible representation.

The specification version, Go toolchain, Node.js toolchain, package-manager lockfile, and dependency versions must be recorded and reproducible.

## 6. User stories

### 6.1 Lab operator

- I can mount a configuration file containing device clients, users, groups, command rules, and an administrative API token.
- I can start the appliance and immediately authenticate a test device.
- I can add a temporary user from the UI or API without editing the baseline.
- I can see that the new user is ephemeral.
- I can test a command authorization request and see exactly which rule matched.
- I can watch live authentication, authorization, and accounting events.
- I can reset all runtime state and return to the baseline.
- I can restart the container and know all temporary changes are gone.

### 6.2 Automation agent

- I can discover MCP tools allowed by my token scopes.
- I can create the same temporary user through MCP that I could create through REST.
- I receive the same validation, revision conflict, and authorization behavior from both APIs.
- I can retrieve a redacted effective configuration and recent events.
- I can never retrieve password, challenge-secret, shared-secret, TLS-key, or token values.

### 6.3 Protocol tester

- I can test ASCII, PAP, CHAP, MS-CHAP v1, MS-CHAP v2, ENABLE, and password-change flows.
- I can test command and session authorization.
- I can send start, stop, and watchdog accounting records.
- I can test multiplexed sessions on one connection.
- I can test malformed lengths, invalid sequence numbers, unsupported actions, and incorrect flags.
- I can run legacy TACACS+ and secure TACACS+ on separate ports.

## 7. Functional requirements

### 7.1 Baseline configuration

The service must load a versioned YAML configuration defining:

- process and listener settings.
- legacy TACACS+ clients and shared-secret references.
- secure TACACS+ clients and certificate identity rules.
- TLS server certificates, trust stores, revocation policy, and SNI profiles.
- users and credentials.
- flat groups.
- authorization rules and response AV pairs.
- accounting/event settings.
- initial API tokens and scopes.
- limits and timeouts.
- UI and HTTP settings.

Validation must be complete before any listener becomes ready.

### 7.2 Runtime overlay

Authorized callers may:

- create runtime-only users, groups, clients, and API tokens.
- override mutable fields of configured objects.
- tombstone configured objects.
- remove runtime-only objects.
- reset all runtime state.

The overlay is memory-only by default. Runtime writes must not modify mounted files.

### 7.3 Configuration reload

Reload may be triggered through:

- `SIGHUP`.
- REST.
- MCP.

Reload must:

- reread the configured source and referenced secret files.
- validate a complete replacement baseline.
- rebase the existing overlay by default.
- reject the candidate if the combined state is invalid.
- retain the previous effective snapshot on failure.
- publish one new revision atomically on success.

### 7.4 Effective configuration export

Export supports:

- baseline-only redacted view.
- runtime-overlay redacted view.
- effective merged redacted view.

Exports never contain secret values. Optional operator-controlled export of password verifier strings requires a separate scope and is disabled by default; clear-equivalent challenge secrets are never exported.

## 8. Domain model

### 8.1 Common metadata

Every administratively visible object includes:

```text
id, display_name?, source, shadows_source?, deleted,
revision_created, revision_updated, effective_revision,
enabled, labels, created_at, updated_at
```

`source` is `config`, `runtime`, or `override` only. Tombstone is not a source value; overlay deletions are exposed as `deleted: true`. `effective_revision` is a read alias of the published snapshot revision.

`labels` are bounded key/value metadata for operator organization. They are not used for security policy unless a future ADR explicitly adds that capability.

### 8.2 Network client

Fields:

- `name`.
- one or more CIDRs.
- match priority.
- enabled flag.
- allowed transport: legacy, TLS, or both through distinct definitions.
- legacy shared-secret reference.
- non-secret shared-secret lifecycle metadata and compiled health status.
- secure certificate identity matcher.
- allowed authentication types.
- allowed authentication services.
- single-connect policy.
- connection and session limits.
- timeouts.
- default groups or policies when explicitly configured.
- labels.

Client definitions that create an unresolved selection tie are invalid.

### 8.3 User

Fields:

- normalized username and display username.
- enabled flag.
- group memberships.
- optional user-specific authorization rules.
- login password verifier for ASCII/PAP.
- separate challenge secret reference for CHAP/MS-CHAP.
- optional ENABLE verifier or challenge secret.
- allowed authentication types and services.
- optional expiry time.
- labels.

Usernames are processed with the RFC-required username profile and are not blindly lowercased.

### 8.4 Group

Groups are intentionally flat.

Fields:

- name.
- enabled flag.
- numeric priority.
- authorization rules.
- default response AV pairs.
- optional allowed clients, services, or authentication types.
- labels.

Groups cannot contain groups. Cycles are therefore impossible.

### 8.5 Authorization rule

Fields:

- stable rule ID.
- description.
- enabled flag.
- match predicates.
- decision: `permit-add`, `permit-replace`, or `deny`.
- returned AV pairs.
- operator-safe reason code.
- optional audit severity.

Supported predicates:

- client definition.
- username or group.
- service and protocol.
- authentication type.
- requested/current privilege level.
- device port.
- remote address or CIDR.
- exact command name.
- ordered command arguments.
- compiled RE2 command pattern.
- required or forbidden AV pairs.
- time window only if an injectable, testable clock feature is explicitly enabled.

Rules are first-match and deterministic. The default is deny.

### 8.6 AV pair

Representation preserves:

- name.
- value, including empty values.
- separator kind: mandatory `=` or optional `*`.
- original order.
- duplicates.

The parser splits only on the first separator. An AV pair has a maximum encoded length of 255 bytes. Arbitrary vendor attributes are retained even when they are not in the standard dictionary.

### 8.7 API token

Fields:

- token ID.
- name.
- hash of a randomly generated high-entropy token.
- scopes.
- creation and expiration times.
- last-used metadata with coarse precision when enabled.
- enabled/revoked state.
- source metadata.

A runtime token value is returned once at creation. Configured token values are loaded from secret files and never returned.

### 8.8 Event

Common fields:

- monotonic event sequence.
- timestamp.
- category and type.
- result code.
- listener/transport.
- client definition name.
- session ID rendered safely.
- snapshot revision.
- redacted request context.
- redacted decision trace summary.
- correlation ID.

Usernames and command text are potentially sensitive and require explicit event-view scope. Metrics never use them as labels.

## 9. State and revision model

### 9.1 Revisions

The state manager owns a monotonically increasing 64-bit revision. It increments once for each successfully published effective snapshot, including:

- runtime mutation.
- runtime reset.
- successful config reload.
- secret reload that changes effective verification material.

Read responses include the active revision. Mutations accept an optional expected revision:

- REST uses `If-Match` or an explicit documented equivalent.
- MCP uses `expected_revision` in the typed input.

A mismatch produces the common `revision_mismatch` error without partial application.

### 9.2 Overlay object rules

- Creating an identity that exists only in the baseline creates an override only when the operation explicitly requests override semantics.
- Updating a baseline object creates or updates an overlay patch.
- Deleting a baseline object creates a tombstone.
- Deleting a runtime object removes it.
- Deleting an override removes the override and reveals the baseline unless the operation explicitly creates a tombstone.
- Reset deletes all overlay entries and tombstones.

These distinctions must be visible in API responses and UI confirmations.

### 9.3 Snapshot consistency

A protocol request uses one snapshot revision for its full decision. Multi-step authentication sessions bind to the snapshot selected at the START packet. A later config change does not alter the in-progress flow. New sessions use the new snapshot.

This avoids credentials or policies changing midway through one authentication exchange.

## 10. TACACS+ wire and connection design

### 10.1 Header processing

The codec must validate:

- supported major and minor versions.
- packet type.
- sequence number and direction parity.
- flags and transport-specific requirements.
- session ID.
- configured maximum body length before allocation.
- exact body component lengths after decode.

The first client packet uses sequence 1. Client packets are odd, server packets are even, and sequence numbers never wrap. Unknown or invalid options follow the required ERROR and session termination behavior.

### 10.2 Legacy transport

- Accept connections only from configured clients.
- Bind a unique shared secret per selected client definition.
- Enforce configurable minimum length and complexity without imposing a maximum below the RFC-required 32-character support point.
- Track non-secret rotation metadata, compute `current`/`due_soon`/`overdue`/`unknown` status, notify operators, and warn on reuse detected through a process-local keyed HMAC fingerprint without exposing the value or fingerprint.
- Apply RFC 8907 body obfuscation.
- Reject packets with the unencrypted flag set.
- Detect likely shared-secret mismatch through invalid decoded lengths and return ERROR where the packet type permits.
- Stop accepting new sessions on a connection after an invalid secret or equivalent connection-level error.
- Close after current valid sessions drain.

Legacy transport is for lab compatibility. Operator documentation must state that it does not provide modern confidentiality or integrity. Co-location with the secure listener is governed by [ADR 0001](decisions/0001-all-in-one-dual-listener-lab.md); new production-like lab profiles should prefer TLS-only or separately isolated instances.

### 10.3 Secure transport

- Listen separately from legacy TACACS+.
- Start TLS immediately.
- Require TLS 1.3 or newer.
- Require mutual certificate authentication in the baseline implementation.
- Validate certificate paths, trust chains, revocation policy, peer identity, and configured client mapping.
- Support SNI profile selection with explicit default identity behavior.
- Implement or formally disposition the TLS Cached Information Extension and configurable TLS 1.3 cipher policy where the selected stack exposes the required hooks.
- Do not allow TLS 1.2 or an in-band upgrade.
- Do not use TACACS+ obfuscation.
- Require the TACACS unencrypted flag to be set for every packet over TLS as RFC 9887 specifies.
- Reject early data and do not enable 0-RTT.
- Make session resumption and ticket lifetime configurable.
- Keep TLS and legacy client definitions and credentials distinct by default.

### 10.4 Single-connect mode

On the first request/reply pair, negotiate the single-connect flag. After negotiation:

- multiple sessions may be multiplexed by session ID.
- packets for one session remain sequential.
- sessions may progress concurrently.
- connection-level reader logic dispatches to bounded session queues.
- a per-connection session cap prevents exhaustion.
- idle and maximum-age timeouts close stale connections.
- late packets for closed/unknown sessions are rejected deterministically.

When single-connect is not negotiated, close the TCP connection after the session completes.

### 10.5 Backpressure

The connection reader must not create unbounded goroutines or queues. When session or global limits are reached, return a protocol-appropriate error when possible and close or drain according to connection state.

Writes on one connection are serialized to preserve packet boundaries. Fairness must prevent one session from starving others.

### 10.6 Connection and session errors

Replies never include secrets, internal traces, or decoder details. `server_msg` is empty for protocol ERROR.

| Condition | Wire | Connection |
|---|---|---|
| Unknown peer / no client match | no packet | close |
| Connection cap reached | no packet | close |
| `TAC_PLUS_UNENCRYPTED_FLAG` on legacy | type-specific ERROR | no new sessions; drain; close |
| Body length-sum mismatch after deobfuscation | type-specific ERROR | no new sessions; drain; close |
| Unknown header type | identical header, seq+1, length 0 | drain; close |
| Unsupported major or sequence 0 | type-specific ERROR if type known | drain; close |
| Body longer than `max_packet_body_bytes` | type-specific ERROR if type known | close |
| Per-connection session cap | type-specific ERROR | stay open if single-connect |
| Active session ID reused with a different type | type-specific ERROR | that session ends |
| Idle timeout or `single_connect.max_lifetime` | none | close |
| Malformed body that is not a length-sum failure | type-specific ERROR | that session ends |
| Invalid accounting flags | ACCT ERROR | that session ends |
| SENDAUTH / SENDPASS / unknown action | AUTHEN ERROR | that session ends |

AAA remains protocol-independent. The PR-10 stub replies ERROR for accepted authentication starts, FAIL for authorization, and SUCCESS for valid accounting flags. Full ASCII and policy are later work.

## 11. Authentication design

### 11.1 Supported flows

Release-blocking support:

- ASCII LOGIN, including username prompt, password prompt, retry limits, NOECHO, PASS, FAIL, ERROR, RESTART, and client abort.
- PAP LOGIN.
- CHAP LOGIN.
- MS-CHAP v1 LOGIN.
- MS-CHAP v2 LOGIN.
- ENABLE authentication.
- ASCII password change.

All protocol versions and one-packet versus multi-packet flow constraints are enforced.

### 11.2 Deprecated and unsupported actions

- SENDPASS is not part of the current protocol and is not implemented.
- SENDAUTH is disabled and explicitly rejected by default because RFC 8907 advises servers not to implement it.
- FOLLOW/redirection is never emitted in normal operation and received deprecated forms are treated according to the secure failure policy.

Explicit rejection is tested; these options are not silently ignored.

### 11.3 Credential separation

A single password hash cannot verify all flows.

- ASCII and PAP use a slow password verifier, preferably Argon2id with configurable parameters.
- CHAP and MS-CHAP require clear-equivalent secret material to calculate the expected challenge response.
- ENABLE may use a distinct verifier or challenge secret.

The configuration supports separate secret references. Operators are warned against reusing the same credential for challenge and non-challenge authentication.

### 11.4 Password change

Password change:

1. verifies the old credential.
2. prompts for and confirms the new password according to configured policy.
3. creates a runtime password-verifier override.
4. never edits the baseline file.
5. emits a redacted security event.

Password change for a user without a mutable runtime credential policy fails clearly. Challenge secrets are not automatically derived from the changed ASCII/PAP password.

### 11.5 Authentication policy

Policy can restrict allowed authentication types globally, per listener, per client, and per user. The most restrictive combination applies.

A challenge-only mode must be available as required by RFC 8907 guidance. Unsupported or disallowed types produce FAIL or RESTART according to the flow and configured compatibility behavior.

## 12. Authorization design

### 12.1 Input normalization

The request is converted to a domain form preserving:

- client identity.
- username.
- port and remote address.
- authentication type and service.
- current privilege level.
- ordered AV pairs.
- exact `cmd` and ordered `cmd-arg` values.
- a display-only normalized command string.

The reported authentication method is retained for observability but not trusted for policy.

### 12.2 Session authorization

A shell authorization request with an empty `cmd` is session based. Rules may return:

- `priv-lvl` from 0 through 15.
- standard session attributes.
- vendor-specific optional or mandatory AV pairs.
- PASS_ADD or PASS_REPL behavior.

### 12.3 Command authorization

A non-empty `cmd` is command based. Rules can match:

- exact command name.
- ordered arguments.
- joined command representation.
- client, group, user, port, remote address, service, and privilege context.

The evaluator does not run a shell parser and does not execute commands. Regexes use Go's RE2-compatible engine and are compiled during snapshot creation.

### 12.4 Decision trace

Every evaluation produces an internal trace with:

- input summary.
- candidate policy sources.
- each evaluated rule ID and match/no-match reason.
- winning rule.
- decision status.
- returned AV pairs.
- default-deny reason when applicable.

Ordinary events include only a compact summary. The full trace is available through an authorized policy-explain operation and is redacted.

### 12.5 Response semantics

- `permit-add` maps to PASS_ADD.
- `permit-replace` maps to PASS_REPL.
- `deny` maps to FAIL.
- internal processing failure maps to ERROR.
- FOLLOW is not emitted.

Mandatory and optional AV-pair separators are preserved in responses.

## 13. Accounting design

### 13.1 Supported records

- START.
- STOP.
- WATCHDOG without update.
- WATCHDOG with update.
- command accounting.
- shell/session accounting.
- connection and system event accounting.
- arbitrary vendor AV pairs.

Invalid flag combinations return accounting ERROR.

### 13.2 Acceptance and acknowledgement

The authoritative 1.0 accounting sink is the bounded in-memory event/accounting ring. A request is acknowledged SUCCESS only after the record is validated, assigned an event ID, and accepted into the ring.

The ring overwrites the oldest record when configured capacity is reached. This is an explicit bounded lab behavior and increments a counter. Optional external exporters consume asynchronously and do not change the protocol acknowledgement unless a future durable mode explicitly says so.

### 13.3 Task correlation

Where present, `task_id` is stored as an opaque string. The server may correlate START, WATCHDOG, and STOP records for display, but it does not assume a format. Missing or unexpected correlation creates diagnostics without inventing protocol failure unless the request itself is invalid.

## 14. Administrative operation design

### 14.1 Canonical operation layer

Operations are identified by stable IDs, for example:

```text
system.status.get
config.effective.get
config.validate
config.reload
config.export
runtime.reset
users.list
users.get
users.create
users.update
users.delete
groups.list
groups.get
groups.create
groups.update
groups.delete
clients.list
clients.get
clients.create
clients.update
clients.delete
tokens.list
tokens.create
tokens.revoke
policy.evaluate
authentication.test
events.list
```

Each operation is implemented once and bound to REST and MCP as defined in `API_PARITY.md`.

### 14.2 Scopes

Initial scope set:

- `state:read`.
- `state:write`.
- `config:reload`.
- `config:export`.
- `policy:test`.
- `events:read`.
- `events:sensitive`.
- `tokens:manage`.
- `runtime:reset`.

Scope matching is exact unless a documented hierarchy is added. A token with `state:write` does not automatically receive token-management or runtime-reset privileges.

### 14.3 API token verification

Tokens are random values with at least 256 bits of entropy. Store a hash suitable for random bearer tokens and compare in constant time. Token IDs allow efficient lookup without storing or logging full token values.

Configured tokens load from secret files. Runtime tokens return once. All API access should use TLS except explicitly isolated localhost development.

### 14.4 Browser authentication

The browser may exchange a bearer token for a short-lived HttpOnly, Secure, SameSite session cookie. The server stores only bounded session metadata and the associated API principal. CSRF protection is mandatory for cookie-authenticated mutations.

The UI must not persist the bearer token in local storage.

## 15. REST design

### 15.1 Conventions

- Base path `/api/v1`.
- JSON request and response bodies.
- OpenAPI 3.1 contract.
- cursor pagination.
- deterministic sort order.
- RFC-compatible timestamps in UTC.
- common problem-details envelope with stable application error code.
- `If-Match` for revision-sensitive writes.
- `Idempotency-Key` for create/reset/reload operations where replay matters.
- unknown mutation fields rejected.
- request body limits enforced before full decode.

### 15.2 Streaming

`GET /api/v1/events/stream` uses SSE. It supports:

- authorization scopes.
- category filters.
- last-event cursor.
- heartbeat comments.
- reset notification when history is no longer available.
- bounded per-subscriber queue.

### 15.3 Health and metrics

- `/health/live`: process is running.
- `/health/ready`: required listeners and initial snapshot are active.
- `/metrics`: optional Prometheus format on the admin listener or a separate configured listener.

Health endpoints expose no sensitive details.

## 16. MCP design

### 16.1 Transport

Use MCP 2026-07-28 Streamable HTTP (`POST /mcp` only). The official Go SDK (`v1.7.0`) is recorded but not imported; the transport is a thin in-tree JSON-RPC adapter approved by [ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md). Do not proxy MCP to REST.

### 16.2 Tools

All mutation and action operations are tools. Tool names are deterministic and stable, for example:

```text
taclab.users.list
taclab.users.create
taclab.groups.update
taclab.policy.evaluate
taclab.runtime.reset
```

Each tool has:

- a precise description.
- closed input schema where appropriate.
- output schema.
- structured content.
- explicit mutating/read-only annotations where supported.
- scope-filtered discovery.

Structured output also includes a text representation when required for compatible clients.

### 16.3 Resources

Useful read-only resources include:

```text
taclab://status
taclab://config/effective
taclab://users
taclab://groups
taclab://clients
taclab://events/recent
```

Resources are convenience views over the same operations and permissions. They never contain secret values.

### 16.4 Event updates

Use `subscriptions/listen` (C8). Notifications carry URI + `subscriptionId` only. Clients pull redacted bodies through `taclab.events.list` / `taclab://events/recent`. REST SSE remains the body firehose. Both share the event ring, cursors, filtering, redaction, and authorization.

### 16.5 Authorization

Lab mode accepts the same scoped bearer token used by REST. The HTTP MCP endpoint validates authorization per request. An optional standards-oriented OAuth mode may be added later behind the same principal/scopes interface.

## 17. REST/MCP parity design

Parity is enforced at three levels:

1. **Implementation parity**: both adapters call one operation handler.
2. **Contract parity**: common request/response fields derive from the same Go types and schemas.
3. **Behavior parity**: table-driven tests invoke both surfaces and compare state, errors, redaction, events, and revision effects.

Protocol-only endpoints are explicitly exempt. The generated parity matrix is committed and CI fails if an operation is missing, has mismatched scopes, or has stale documentation.

## 18. React/TypeScript UI design

### 18.1 Technology

- React.
- TypeScript in strict mode.
- Vite or a similarly small build tool.
- generated API client from OpenAPI.
- a query/cache library for server state.
- a form/schema validation library aligned with generated types.
- a router for client-side navigation.
- a focused accessible component layer rather than a large custom design system.

### 18.2 Pages

- Sign-in/token exchange.
- Dashboard and listener status.
- Users.
- Groups and authorization rules.
- Network clients, including legacy shared-secret lifecycle status and reuse/rotation warnings.
- API tokens.
- Live events/accounting.
- Authentication test console.
- Policy authorization/explanation console.
- Effective configuration viewer/export.
- Runtime reset and reload controls.
- About/build/specification status.

### 18.3 Reactive behavior

- REST query results include revision.
- SSE state-change events invalidate relevant cached queries.
- Lists update without full-page reload.
- Forms preserve unsaved input when unrelated events arrive.
- stale updates receive a revision conflict UI with reload and compare options.
- optimistic updates are allowed only where rollback is safe and server validation remains authoritative.

### 18.4 Source visibility

Every editable row and detail page shows:

- `CONFIG` for baseline objects.
- `RUNTIME` for ephemeral objects.
- `OVERRIDE` for baseline objects with runtime changes.

Deleting or updating a configured object clearly explains tombstone/override behavior. Runtime objects display “removed on restart.”

### 18.5 Security and accessibility

- No secret values are rendered after one-time token creation.
- All text is escaped by default.
- destructive operations require explicit confirmation and describe scope.
- keyboard navigation and visible focus are required.
- forms have labels, descriptions, field errors, and an error summary.
- live regions announce asynchronous success/failure without flooding screen readers.
- color is not the only indicator of status.

## 19. Configuration design

The detailed schema is in `CONFIGURATION.md`. Core principles:

- one top-level version.
- strict field validation.
- secret values referenced by file, not embedded by default.
- explicit durations and limits.
- deterministic ordered rule lists.
- no YAML anchors as a required feature; expanded values are validated after decoding.
- enforceable legacy shared-secret length/complexity policy, lifecycle metadata, rotation notification, and reuse warning.
- startup errors identify a safe path and reason without echoing secret content.
- a CLI validation mode is provided.

Suggested commands:

```bash
taclabd validate --config /etc/taclab/config.yaml
taclabd print-effective --config /etc/taclab/config.yaml --redacted
taclabd serve --config /etc/taclab/config.yaml
```

## 20. Observability design

### 20.1 Logs

Structured JSON by default in containers. Fields include timestamp, level, event, operation, listener, client definition, result code, revision, and correlation ID.

Never log credential input, token values, shared secrets, challenge material, or TLS private keys. Command text and username logging are configurable and redacted by default.

### 20.2 Metrics

Initial metrics:

- active connections by listener and client definition.
- accepted/rejected connections.
- active sessions.
- authentication outcomes by type.
- authorization outcomes.
- accounting outcomes and overwritten ring records.
- packet and protocol errors.
- API operation counts and latency.
- MCP tool counts and latency.
- state revision and reload outcomes.
- legacy shared-secret lifecycle counts by bounded status (`current`, `due_soon`, `overdue`, `unknown`) and warning totals, with no client ID or fingerprint label.
- event subscribers and dropped/reset subscribers.
- Go runtime metrics.

Labels must remain bounded.

### 20.3 Build information

Expose version, commit, build time, Go version, UI version, config schema version, TACACS conformance version, and MCP specification version. Do not expose file paths or secret metadata to unauthenticated callers.

## 21. Security design

### 21.1 Threat model highlights

Threats include:

- malicious or malformed TACACS clients.
- wrong shared secrets causing garbage decoded lengths.
- connection and session exhaustion.
- credential and token disclosure through logs or API responses.
- weak, stale, or unintentionally reused legacy shared secrets.
- command authorization bypass through normalization differences.
- stale-write overwrites.
- cross-surface authorization drift.
- browser CSRF or token theft.
- TLS downgrade or invalid client certificate acceptance.
- unbounded event subscribers.
- path traversal in embedded asset serving.

### 21.2 Controls

- known-client allowlist.
- bounded reads and allocations.
- per-client/global rate and concurrency limits.
- fail-closed policy.
- separate legacy and TLS listeners.
- TLS 1.3 minimum and mutual authentication.
- strict request decoding.
- common scope enforcement.
- revision preconditions.
- secret-specific types and redacted views.
- shared-secret complexity validation, lifecycle notification, and process-local keyed-HMAC reuse detection.
- read-only container filesystem.
- non-root runtime.
- dependency scanning and SBOM.
- protocol fuzzing and race testing.

### 21.3 Cryptography

- Use standard-library or well-reviewed cryptographic implementations.
- Do not invent cryptographic primitives.
- Legacy TACACS obfuscation is implemented only for protocol compatibility.
- Password hashing parameters are configurable and benchmarked.
- API tokens use cryptographically secure randomness.
- TLS private keys remain outside the image.

## 22. Performance design

Primary hot paths:

- packet header/body decode and encode.
- legacy obfuscation.
- connection/session dispatch.
- user/client lookup.
- authorization rule evaluation.
- event ring append.
- API list serialization.

Design choices:

- immutable compiled snapshots.
- longest-prefix client index compiled ahead of time.
- normalized user/group indexes.
- regex compilation at state publication.
- no database round trip.
- bounded pools only where benchmarks prove benefit.
- avoid unsafe zero-copy tricks unless an ADR and fuzz/race evidence justify them.

Absolute performance targets and regression thresholds are defined in `TESTING_AND_BENCHMARKS.md`.

## 23. Deployment design

One multi-stage image:

1. Build the React application.
2. Compile and test the Go service.
3. Copy the static binary/assets and CA bundle into a minimal non-root runtime image.

Reference Compose mounts:

- configuration read-only.
- API token secret.
- legacy shared-secret files.
- TLS certificate, key, and CA material.
- challenge-secret files.

The root filesystem is read-only. Writable paths are explicit tmpfs mounts. Runtime state is not stored on a volume.

A single replica is required while the overlay is memory-only.

## 24. Testing strategy

Required layers:

- pure codec unit tests with golden packet fixtures.
- independent algorithm test vectors for CHAP and MS-CHAP.
- policy unit and golden explanation tests.
- state compiler and overlay property tests.
- connection state-machine integration tests.
- REST and MCP contract tests.
- parity equivalence tests.
- React component and end-to-end tests.
- Compose end-to-end tests using an independent test client.
- interoperability tests against at least one external server/client implementation and available lab devices.
- parser/state fuzzing.
- race tests.
- benchmark and load tests.
- secret leakage tests.

No protocol behavior is accepted based only on internal client/server tests that share the same codec.

## 25. Release acceptance

### 25.1 Protocol acceptance

- All RFC 8907 `MUST` and `MUST NOT` rows pass.
- All RFC 9887 mandatory server rows pass.
- Every supported authentication flow passes positive and negative fixtures.
- single-connect tests pass under concurrent sessions and race detector.
- invalid accounting flags return ERROR.
- PASS_ADD and PASS_REPL behavior passes independent fixtures.
- cleartext legacy packets are rejected.
- TLS packets use the required unencrypted flag and no obfuscation.

### 25.2 State acceptance

- invalid reload preserves the active revision.
- runtime reset restores baseline behavior.
- restart removes runtime objects.
- config/runtime/override/tombstone semantics pass table-driven tests.
- secrets never appear in exports.

### 25.3 API acceptance

- parity matrix has no missing parity-required binding.
- equivalent REST and MCP operations produce equivalent state and errors.
- scope-filtered MCP discovery works.
- browser session flow avoids local-storage token persistence.
- stale writes are rejected.

### 25.4 UI acceptance

- all required pages function against the real API.
- live events update reactively.
- source badges and revision conflicts are visible.
- keyboard-only primary workflows pass.
- destructive and secret-creation flows are clear.

### 25.5 Deployment acceptance

- reference Compose starts from a clean checkout and secret directory.
- image runs non-root and read-only.
- legacy and TLS test clients connect on mapped ports.
- readiness reflects listener health.
- restart restores baseline.
- image scan and SBOM pass release policy.

## 26. Open design decisions requiring ADRs during implementation

- Exact Go TACACS codec/library reuse versus internal implementation after the protocol spike.
- Username normalization library and canonical lookup representation.
- Certificate revocation strategy available in the chosen Go TLS stack.
- TLS Cached Information Extension support versus an approved RFC `SHOULD` disposition.
- TLS session resumption behavior, advertised ticket-lifetime control, certificate revalidation constraints, and ticket-linkability mitigation.
- TLS 1.3 cipher-policy configurability where Go intentionally manages cipher selection.
- Whether external TLS PSK support is feasible without a nonstandard TLS stack.
- Exact OpenAPI/schema generation toolchain.
- UI component library, if any.
- Detailed rate-limiting algorithm and defaults.
- Sensitive event field retention defaults.
- Whether optional SQLite accounting is included after 1.0.

Each ADR must preserve the goals, conformance gates, and parity rules in this packet.
