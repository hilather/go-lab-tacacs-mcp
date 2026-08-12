# Configuration and Runtime State Contract

Status: implementation contract  
Applies to: config loader, validators, state compiler, REST API, MCP server, UI, export, and deployment  
Last updated: 2026-08-12

## 1. Purpose

TacLab must reproduce a declared lab baseline while still permitting temporary changes during an experiment. The configuration subsystem therefore has two distinct responsibilities:

1. Load and validate a versioned, read-only baseline configuration.
2. Maintain a process-local runtime overlay for ephemeral users, groups, clients, policies, and API tokens.

The effective state is computed as:

```text
validated defaults
+ validated baseline configuration
+ validated runtime overlay
= immutable compiled snapshot
```

The compiled snapshot is the only state consumed by TACACS request processing. A failed startup, reload, or runtime mutation must never partially publish state.

## 2. Non-negotiable rules

- Configuration is strict and versioned. Unknown fields are errors unless a versioned extension point explicitly permits them.
- The baseline file is never rewritten by the running service.
- Runtime changes are memory-only in the initial product and disappear after restart.
- A runtime object may shadow a baseline object with the same stable ID when `runtime.allow_shadowing` is enabled.
- Deleting a baseline object through an API creates a runtime tombstone; it does not edit the source file.
- Secrets are referenced, not embedded, in examples and production guidance.
- Secret values are write-only and must never appear in API responses, MCP results, UI state, logs, traces, metrics labels, event payloads, exports, panic messages, or validation errors.
- The complete candidate configuration is parsed, resolved, cross-referenced, compiled, and tested for invariants before publication.
- Existing effective state remains active when a reload fails.
- Every successful publication increments the effective-state revision.
- Deterministic input must produce deterministic compiled output, policy order, API output order, and exported configuration.

## 3. Configuration sources and precedence

### 3.1 Sources

TacLab recognizes these sources:

| Priority | Source | Mutability | Lifetime |
|---:|---|---|---|
| 1 | Built-in safe defaults | Compile-time | Process |
| 2 | Baseline YAML file | Read-only | Across restarts |
| 3 | Referenced secret files | Read-only | Across restarts or secret rotation |
| 4 | Runtime overlay | API-managed | Until reset or restart |

Higher-priority sources override lower-priority sources only at explicitly supported object boundaries. Agents must not implement arbitrary deep merging of partially specified objects because it creates ambiguous policy and secret behavior.

### 3.2 Object replacement

Objects are keyed by stable IDs. A runtime object with the same ID as a baseline object replaces the baseline object as a complete logical object after validation. It does not recursively merge unspecified fields.

Example:

```text
baseline user id: operator
runtime user id: operator
result: runtime user is effective; baseline user remains available for reset/rebase
```

### 3.3 Tombstones

A runtime deletion of a baseline-defined object records a tombstone containing:

- Object kind.
- Stable object ID.
- Creation timestamp.
- Actor token ID or UI session ID.
- Effective revision at which the deletion was accepted.

Tombstones are included in sanitized state inspection but excluded from normal user/group/client lists unless `include_deleted=true` is explicitly requested by an authorized caller.

### 3.4 Revision model

The state store exposes:

```go
type Revision uint64

type Snapshot struct {
    Revision      Revision
    BaselineHash  string
    OverlayHash   string
    CompiledAt    time.Time
    // Immutable compiled indexes follow.
}
```

Mutation requests that can lose updates must support an expected revision using REST `If-Match` or an equivalent typed MCP argument. A stale expected revision returns a conflict without mutation.

## 4. File format and schema policy

### 4.1 Format

- Primary format: YAML 1.2-compatible input.
- Canonical internal representation: typed Go structures.
- Canonical export: deterministic YAML with stable ordering.
- File extension: `.yaml` or `.yml`.
- Encoding: UTF-8.
- Maximum baseline file size: configurable; default 4 MiB.
- YAML aliases and anchors: rejected by default to prevent surprising expansion and review ambiguity.
- Duplicate mapping keys: rejected.
- Multiple YAML documents in one file: rejected.

### 4.2 Schema version

The root must include:

```yaml
schema_version: 1
```

A missing or unsupported version is a fatal validation error. Schema migrations must be explicit, deterministic, documented, and covered by golden tests.

### 4.3 Unknown fields

Unknown fields are errors. The loader must return a path-qualified message such as:

```text
clients[1].authentcation: unknown field; did you mean authentication?
```

Error text must not echo a secret value.

## 5. Secret reference model

### 5.1 Supported reference

The required production-safe mechanism is a file reference:

```yaml
shared_secret:
  file: /run/secrets/tacacs_shared_secret
```

The implementation may support environment references for local development only when explicitly enabled:

```yaml
shared_secret:
  environment: TACLAB_TACACS_SHARED_SECRET
```

Environment references must be disabled by default in the reference container because environment values are easier to expose through diagnostics and orchestration metadata.

### 5.2 Secret-file behavior

- Read the file as bytes.
- Reject directories, symlinks when strict mode is enabled, oversized files, world-writable files, and files not readable by the TacLab process.
- Trim one terminal CRLF or LF for text secrets unless `preserve_trailing_newline: true` is configured.
- Do not trim other whitespace silently.
- Record only the reference path and a process-local keyed HMAC fingerprint in internal diagnostic state. The HMAC key is generated at process start, is never persisted, and is never exposed.
- Never include the fingerprint in metrics labels.
- Zero temporary buffers where practical, while acknowledging normal Go garbage-collector limitations.

### 5.3 Secret types

Secret references are typed. A value intended for one purpose must not be reused accidentally for another.

| Secret type | Purpose |
|---|---|
| `legacy_shared_secret` | RFC 8907 packet-body obfuscation for a legacy client |
| `login_verifier` | Slow password verifier for ASCII/PAP validation |
| `challenge_secret` | Reversible/clear secret material required to calculate CHAP/MS-CHAP responses |
| `enable_verifier` | ENABLE password verifier |
| `api_bearer_token` | Bootstrap REST/MCP token input |
| `tls_private_key` | TLS server identity key |
| `tls_psk` | Optional RFC 9887 external TLS PSK; never shared with legacy obfuscation |

Agents must enforce separation between legacy TACACS shared secrets and TLS PSKs.

## 6. Complete annotated baseline example

The following example defines a reproducible lab baseline. It is intentionally explicit rather than minimal.

```yaml
schema_version: 1

metadata:
  name: branch-routing-lab
  description: Reproducible TACACS lab for router and switch authorization testing
  labels:
    environment: lab
    owner: network-engineering

server:
  instance_id: taclab-01
  shutdown_grace: 15s
  startup_failure_mode: fail_closed
  log_level: info

runtime:
  persistence: memory
  allow_shadowing: true
  delete_baseline_behavior: tombstone
  reload_overlay_behavior: rebase
  reset_requires_scope: runtime:reset
  max_objects:
    users: 10000
    groups: 1000
    clients: 2000
    api_tokens: 1000

security:
  legacy_shared_secrets:
    minimum_length_characters: 16
    minimum_character_classes: 3
    reject_known_weak_values: true
    warn_on_reuse: true
    default_rotation_interval: 90d
    rotation_warning_before: 14d

listeners:
  legacy_tacacs:
    enabled: true
    bind: 0.0.0.0:4949
    advertised_port: 49
    read_timeout: 15s
    write_timeout: 15s
    idle_timeout: 60s
    handshake_timeout: 10s
    max_connections: 4096
    max_sessions_per_connection: 1024
    max_packet_body_bytes: 65536
    single_connect:
      enabled: true
      max_lifetime: 10m
      idle_timeout: 60s

  secure_tacacs:
    enabled: true
    bind: 0.0.0.0:4300
    advertised_port: 300
    read_timeout: 15s
    write_timeout: 15s
    idle_timeout: 60s
    handshake_timeout: 10s
    max_connections: 4096
    max_sessions_per_connection: 1024
    max_packet_body_bytes: 65536
    single_connect:
      enabled: true
      max_lifetime: 10m
      idle_timeout: 60s
    tls:
      minimum_version: TLS1.3
      identities:
        default_id: lab-default
        require_sni: false
        profiles:
          - id: lab-default
            server_names:
              - tacacs.lab.example
            certificate_chain:
              file: /etc/taclab/certs-public/server-chain.pem
            private_key:
              file: /run/secrets/tacacs_server_key
      client_authentication: require_and_verify_certificate
      client_ca_bundle:
        file: /etc/taclab/certs-public/client-ca.pem
      revocation:
        mode: configured_crl
        crl_bundle:
          file: /etc/taclab/certs-public/client-crl.pem
      session_resumption:
        enabled: true
        ticket_lifetime: 24h
        recheck_client_revocation: true
      reject_early_data: true

  http:
    enabled: true
    bind: 0.0.0.0:8080
    read_header_timeout: 5s
    read_timeout: 30s
    write_timeout: 30s
    idle_timeout: 60s
    max_request_body_bytes: 2097152
    trusted_proxy_cidrs: []
    tls:
      enabled: false

api:
  mode: lab_static_bearer
  ui_session:
    enabled: true
    lifetime: 30m
    idle_timeout: 10m
    cookie_secure: false
    cookie_same_site: strict
  bootstrap_tokens:
    - id: lab-admin
      token:
        file: /run/secrets/api_admin_token
      scopes:
        - state:read
        - state:write
        - config:reload
        - config:export
        - policy:test
        - events:read
        - tokens:manage
        - runtime:reset
      expires_at: null
  rate_limits:
    enabled: true
    per_token_requests_per_second: 50
    per_token_burst: 100
    unauthenticated_requests_per_second: 5
    unauthenticated_burst: 10

limits:
  max_username_bytes: 253
  max_port_bytes: 253
  max_remote_address_bytes: 253
  max_authentication_rounds: 16
  max_authorization_arguments: 256
  max_argument_bytes: 65535
  max_command_bytes: 65535
  max_policy_trace_steps: 1000
  max_event_payload_bytes: 65536

clients:
  - id: lab-switches
    display_name: Lab switches
    priority: 100
    enabled: true
    match:
      source_cidrs:
        - 10.20.0.0/16
      transports:
        - legacy
    legacy:
      shared_secret:
        file: /run/secrets/lab_switches_tacacs_secret
      shared_secret_lifecycle:
        last_rotated_at: 2026-08-01T00:00:00Z
        rotation_interval: 90d
    authentication:
      allowed_methods:
        - ascii
        - pap
        - chap
        - mschapv1
        - mschapv2
        - enable
        - ascii_chpass
      default_service: login
    authorization:
      default_group_ids:
        - readonly
    accounting:
      enabled: true
      accept_start: true
      accept_stop: true
      accept_watchdog: true

  - id: secure-routers
    display_name: TLS lab routers
    priority: 50
    enabled: true
    match:
      source_cidrs:
        - 10.30.0.0/16
      transports:
        - tls
      certificate:
        dns_sans:
          - router-01.lab.example
          - router-02.lab.example
        ip_sans:
          - 10.30.0.11
          - 10.30.0.12
    authentication:
      allowed_methods:
        - ascii
        - pap
        - chap
        - mschapv1
        - mschapv2
        - enable
        - ascii_chpass
    authorization:
      default_group_ids:
        - readonly
    accounting:
      enabled: true

groups:
  - id: administrators
    display_name: Full administrators
    priority: 10
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "15"
    command_rules:
      - id: permit-all
        priority: 10
        action: permit
        command:
          pattern: ".*"
        arguments:
          pattern: ".*"
        reason: Full lab administration
    default_command_action: deny

  - id: readonly
    display_name: Read-only operators
    priority: 100
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "1"
    command_rules:
      - id: show
        priority: 10
        action: permit
        command:
          exact: show
        arguments:
          pattern: ".*"
        reason: Permit operational show commands
      - id: ping
        priority: 20
        action: permit
        command:
          exact: ping
        arguments:
          pattern: ".*"
      - id: traceroute
        priority: 30
        action: permit
        command:
          pattern: "^(traceroute|traceroute6)$"
        arguments:
          pattern: ".*"
      - id: deny-everything-else
        priority: 10000
        action: deny
        command:
          pattern: ".*"
        arguments:
          pattern: ".*"
        reason: Default deny
    default_command_action: deny

users:
  - id: lab-admin
    display_name: Lab Administrator
    enabled: true
    group_ids:
      - administrators
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_admin_argon2id
      challenge:
        secret:
          file: /run/secrets/lab_admin_challenge_secret
      enable:
        verifier:
          file: /run/secrets/lab_admin_enable_argon2id
    restrictions:
      client_ids: []
      valid_after: null
      valid_before: null

  - id: lab-readonly
    display_name: Read-only Lab User
    enabled: true
    group_ids:
      - readonly
    credentials:
      login:
        verifier:
          file: /run/secrets/lab_readonly_argon2id
    restrictions:
      client_ids:
        - lab-switches
        - secure-routers

events:
  ring_buffer_capacity: 10000
  include_successful_authentication: true
  include_failed_authentication: true
  include_authorization: true
  include_accounting: true
  redact_user_input: true
  stdout:
    enabled: true
    format: json

observability:
  metrics:
    enabled: true
    bind: 127.0.0.1:9090
    path: /metrics
  tracing:
    enabled: false
  profiling:
    enabled: false
```

## 7. Root sections

### 7.1 `metadata`

Metadata is descriptive and must not affect policy decisions. Labels are bounded strings and must never contain secret data.

### 7.2 `server`

Controls process-wide lifecycle and logging behavior. `instance_id` is stable within a deployment and appears in events and health responses. It is not an authentication credential.

### 7.3 `runtime`

Required initial behavior:

- `persistence` must equal `memory`.
- `reload_overlay_behavior` supports `rebase` and `reset`; `rebase` is the default.
- Object limits are enforced before allocation-heavy compilation.
- Runtime reset is atomic and creates a new state revision.

A future persistence adapter requires a separate design approval and must not change default lab behavior.

### 7.4 `security`

The `legacy_shared_secrets` policy is a server-management control required for safe RFC 8907 operation. It applies whenever a legacy secret is resolved from baseline or runtime input.

- `minimum_length_characters` is enforceable and defaults to at least 16. The implementation must accept shared keys of 32 or more characters without truncation.
- `minimum_character_classes` is an integer from 0 through 4 and counts ASCII lowercase, uppercase, digit, and symbol classes. A value of 0 disables the class-count rule without disabling the length rule.
- `reject_known_weak_values` rejects a maintained, non-secret list of obvious lab defaults such as `password` or `changeme`. Error messages name the policy violation, never the submitted value.
- `warn_on_reuse` compares process-local keyed HMAC fingerprints and emits a warning when one effective secret is assigned to multiple legacy clients. Fingerprints are never returned or used as metric labels.
- `default_rotation_interval` defines the due date when a client does not override it. A zero duration disables scheduling but must produce an operator warning.
- `rotation_warning_before` defines when status changes from `current` to `due_soon`.

Each legacy client may provide `shared_secret_lifecycle.last_rotated_at` and an optional `rotation_interval`. The compiled client view exposes only `current`, `due_soon`, `overdue`, or `unknown`, plus dates derived from non-secret metadata. The server emits bounded, redacted lifecycle warnings at startup, reload, and state publication; it must not repeatedly flood logs or events.

Runtime-created or updated legacy clients must provide the same lifecycle metadata unless an authorized explicit override marks it `unknown`. The UI, REST, and MCP surfaces must keep lifecycle status and validation warnings in parity while keeping secret input write-only.

### 7.5 `listeners`

Listener configuration is not runtime-mutable in the first release. Changing listener addresses, TLS identity, or global connection limits requires a configuration reload or process restart.

Legacy and secure TACACS must have distinct bind addresses/ports. Secure TACACS begins TLS immediately and cannot share a port with the legacy listener. Secure TLS identities support SNI-based profile selection with an explicit default; every profile has its own certificate-chain and private-key references. Session-resumption settings include an enable switch, requested ticket lifetime, and revocation-recheck policy. If the selected Go TLS implementation cannot honor a configured RFC `SHOULD` exactly, configuration must reject the unsupported value and the release must carry the required ADR rather than silently approximating it.

### 7.6 `api`

Bootstrap token values are resolved from secret references. The effective API exposes token metadata only:

```json
{
  "id": "lab-admin",
  "source": "config",
  "scopes": ["state:read", "state:write"],
  "expires_at": null,
  "has_secret": true
}
```

A runtime-created token is returned in full exactly once at creation time. Subsequent reads return only metadata and a non-secret token ID.

### 7.7 `limits`

Limits are security boundaries. Reducing a limit through reload is permitted only when the new configuration itself compiles. Existing sessions may complete under the old snapshot; new sessions use the new limits.

### 7.8 `clients`

A client identifies a Network Access Server or a group of devices. Matching uses a deterministic order:

1. Listener/transport compatibility.
2. Explicit certificate identity constraints for TLS, when configured.
3. Most-specific source CIDR prefix.
4. Lowest numeric client priority.
5. Lexicographic stable client ID as the final deterministic tie-breaker.

Validation must reject indistinguishable client definitions unless an explicit ordering makes the result unambiguous.

For a legacy connection, a selected client must have a legacy shared secret. Its resolved value must satisfy the configured length/complexity policy, and its lifecycle metadata is compiled into a non-secret health status. Secret reuse produces a warning when enabled but does not reveal the shared value or fingerprint. For a TLS connection, client identity must satisfy the configured mutual-TLS policy; the legacy shared secret is not used for packet protection.

### 7.9 `groups`

Initial group relationships are flat. Nested groups are out of scope because they complicate deterministic policy explanation and cycle handling without adding value to the intended lab use.

Group priority controls inter-group rule order. Rule priority controls order inside a group. Duplicate priorities are permitted only when the stable rule ID produces a documented deterministic tie-breaker; the recommended validation profile rejects duplicates.

### 7.10 `users`

A user can hold zero or more groups. A user with no applicable permit policy fails authorization by default.

Credential capabilities are explicit:

| Credential material | Supported authentication behavior |
|---|---|
| Slow login verifier | ASCII login and PAP verification |
| Challenge secret | CHAP, MS-CHAP v1, and MS-CHAP v2 calculations |
| Enable verifier | ENABLE verification |
| Login verifier plus a controlled update path | ASCII password-change flow |

The API must refuse to claim a method is available when the required credential material is absent.

### 7.11 `events`

The ring buffer is bounded. Event publication must not block TACACS response processing indefinitely. Backpressure behavior and dropped-event counters are documented in `DESIGN.md` and tested.

## 8. Command and service policy representation

### 8.1 Attribute preservation

Authorization attributes have a name, separator, and value. The separator is significant:

```go
type Attribute struct {
    Name      string
    Separator byte // '=' mandatory, '*' optional
    Value     string
}
```

Agents must not flatten an AV pair into a normal map because duplicate attributes, input order, and separator semantics may matter.

### 8.2 Pattern engine

Regular expressions use Go's RE2-compatible `regexp` package. This avoids catastrophic backtracking. Patterns are compiled during snapshot construction, never on the request hot path.

Each command rule may select exact or regular-expression matching. Exactly one form is allowed per field.

### 8.3 Command normalization

The request's command and argument attributes are preserved for protocol reporting. Policy evaluation additionally creates a normalized view:

- `cmd` is the command token.
- `cmd-arg` values retain order.
- A single display string joins tokens for explanation only.
- No shell parsing, quote expansion, environment expansion, or command execution occurs.
- Empty and missing attributes remain distinguishable.

### 8.4 Default behavior

- Authentication: deny when no enabled user and usable credential match.
- Service authorization: deny when no applicable permit rule matches.
- Command authorization: deny when no applicable permit rule matches.
- Accounting: reject malformed records; otherwise acknowledge valid configured record types even if event export is degraded.

## 9. Runtime API object rules

### 9.1 Runtime-created users

A runtime user may be created with:

- A submitted password that is immediately converted to a slow verifier and discarded.
- Optional challenge secret material retained only in process memory when challenge-response methods are required.
- Optional ENABLE password converted to a verifier.
- Group references.
- Client/time restrictions.

Read operations never return any submitted secret.

### 9.2 Runtime-created API tokens

Creation sequence:

1. Authorize `tokens:manage`.
2. Generate at least 256 bits of cryptographically secure random token material.
3. Store only a verification digest and token metadata.
4. Return the bearer token exactly once.
5. Emit a redacted audit event.

### 9.3 Source and effective metadata

Every managed object response includes:

```json
{
  "id": "operator",
  "source": "runtime",
  "shadows_source": "config",
  "effective_revision": 42,
  "created_at": "2026-08-12T15:00:00Z",
  "updated_at": "2026-08-12T15:00:00Z"
}
```

Timestamps are metadata only and must not change policy ordering.

## 10. Reload behavior

### 10.1 Trigger

A reload may be triggered by:

- A configured signal.
- An authenticated REST operation.
- The parity-equivalent MCP operation.
- An explicitly enabled file watcher.

File watching is disabled by default in the reference deployment to avoid editor-write races and non-deterministic lab changes.

### 10.2 Atomic algorithm

```text
1. Read candidate baseline bytes.
2. Parse with strict YAML rules.
3. Resolve secret references into typed secret holders.
4. Validate local field constraints.
5. Validate cross-object references and ambiguity rules.
6. Rebase or clear a copy of the current overlay according to policy.
7. Compile regexes, CIDR indexes, credential indexes, and client matchers.
8. Run snapshot invariants and optional self-checks.
9. Compute sanitized baseline and overlay hashes.
10. Atomically publish the new snapshot.
11. Emit success event with the new revision.
```

Any failure before step 10 leaves the previous snapshot untouched.

### 10.3 Rebase conflicts

When a baseline reload conflicts with runtime state:

- A valid runtime replacement continues to shadow the new baseline object.
- A runtime object referring to a removed group/client fails rebase validation unless the runtime object is also removed.
- A tombstone continues to hide a baseline object with the same ID.
- An invalid rebase rejects the entire reload; it must not silently drop runtime objects.

A separate `validate_candidate` operation can preview errors before reload.

## 11. Export behavior

### 11.1 Sanitized effective export

The default export contains effective non-secret data and secret placeholders:

```yaml
credentials:
  login:
    verifier:
      redacted: true
      source: file
```

It must never serialize the in-memory challenge secret or runtime bearer token.

### 11.2 Replication bundle export

A future replication bundle may include:

- Sanitized effective YAML.
- A manifest of required secret names and purposes.
- Certificate public material.
- Conformance and version metadata.

It must not include private keys or secret values unless a separate, explicit encrypted-backup design is approved. Such backup functionality is not part of the initial implementation.

## 12. Validation categories

Validation errors use stable machine-readable codes and human-readable paths.

| Category | Example code | Example |
|---|---|---|
| Syntax | `CONFIG_YAML_INVALID` | Bad indentation or scalar type |
| Schema | `CONFIG_UNKNOWN_FIELD` | Misspelled field |
| Secret | `SECRET_FILE_UNREADABLE` | Missing Docker secret |
| Secret policy | `SHARED_SECRET_POLICY_VIOLATION` | Legacy key is too short, too weak, or otherwise disallowed |
| Secret lifecycle | `SHARED_SECRET_ROTATION_OVERDUE` | Legacy key rotation date has passed; warning by default, error only in an explicit strict profile |
| Reference | `GROUP_NOT_FOUND` | User refers to unknown group |
| Ambiguity | `CLIENT_MATCH_AMBIGUOUS` | Equal CIDR and priority |
| Protocol | `AUTH_METHOD_CREDENTIAL_MISSING` | MS-CHAP enabled without challenge secret |
| Security | `TLS_VERSION_UNSUPPORTED` | TLS 1.2 configured for secure TACACS |
| Limit | `OBJECT_LIMIT_EXCEEDED` | Too many runtime users |
| Policy | `REGEX_INVALID` | Invalid command expression |
| Revision | `REVISION_CONFLICT` | Stale mutation precondition |

The same codes must map consistently through REST, MCP, events, logs, and UI messages.

## 13. Configuration test requirements

At minimum, implement:

- Golden parse and canonical-export tests.
- Unknown-field, duplicate-key, multi-document, alias, oversized-input, and invalid-UTF-8 tests.
- Secret-file permission and missing-file tests.
- Legacy shared-secret length, configurable complexity, 32-plus-character acceptance, known-weak rejection, reuse warning, lifecycle status, and due/overdue notification tests.
- Cross-reference tests for every object relationship.
- Ambiguous client-match tests.
- Credential-capability tests for every authentication method.
- Runtime replacement and tombstone tests.
- Reload/rebase rollback tests.
- Revision-conflict tests through operation, REST, and MCP layers.
- Deterministic output tests across repeated runs.
- Secret-canary tests proving redaction from every output surface.
- Fuzz tests for YAML decoding boundaries and runtime mutation payloads.
- Benchmarks for parse, compile, rebase, client-index construction, and snapshot publication at small and maximum reference sizes.

## 14. Agent checklist for configuration changes

Before completing a configuration-related task, the implementing agent must confirm:

- [ ] The typed Go schema and validation behavior are updated.
- [ ] The canonical example and field documentation are updated.
- [ ] REST and MCP schemas expose identical mutable fields and validation semantics.
- [ ] UI forms and generated client types are updated where applicable.
- [ ] Backward compatibility and schema-version impact are documented.
- [ ] A regression test covers the changed behavior or defect.
- [ ] Secret-redaction tests cover any new field that may contain sensitive data.
- [ ] Shared-secret policy, reuse detection, and rotation-status behavior remain represented across config, REST, MCP, UI, events, and operator docs when affected.
- [ ] Compile/reload benchmarks are added or rerun when the hot path or data shape changes.
- [ ] Golden exports are intentionally regenerated and reviewed.
- [ ] `docs/DESIGN.md`, `docs/API_PARITY.md`, and the example configuration remain consistent.
