# TacLab 1.0 operator guide

Status: 1.0 operator contract  
Product: TacLab (`taclabd`)  
Last updated: 2026-08-13

This is the operator-facing 1.0 guide. Protocol and schema details stay in [CONFIGURATION.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md) and [LAB_DEPLOYMENT.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md).

## 1. What you are running

TacLab is a **single-replica lab appliance**, not a production AAA cluster.

| Surface | Host port | Role |
|---|---|---|
| Legacy TACACS+ | 49 → 4949 | RFC 8907, per-client shared secret, obfuscation |
| Secure TACACS+ | 300 → 4300 | RFC 9887 TLS 1.3 mTLS |
| HTTP admin | 8080 | UI, `/api/v1`, `/mcp`, health |

Runtime overlay is **memory-only**. Restart or `runtime.reset` restores the YAML baseline. Do not put the overlay on a volume.

When both TACACS listeners are enabled, status/UI/logs show a **co-located lab topology** warning. That topology is a lab convenience ([ADR 0001](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0001-all-in-one-dual-listener-lab.md)). Production-like tests should use the TLS-only Compose overlay or separate hosts.

## 2. Install and start (Compose)

Prerequisites: Linux, Docker Compose v2, host ports 49/300/8080 (or the high-port smoke overlay).

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
go run ./tools/labgen deployments/compose
docker compose -f deployments/compose/compose.yaml up -d --build
```

TLS-only (no host port 49, no legacy listener):

```bash
docker compose -f deployments/compose/compose.yaml \
  -f deployments/compose/compose.tls-only.yaml up -d --build
```

Health: `taclabd healthcheck --url http://127.0.0.1:8080/health/ready` (Compose uses this).

Acceptance: `make lab-test` (high host ports, ephemeral PKI, LAB-* suite).

## 3. Configuration and secrets

- Baseline: one YAML document, `schema_version: 1`, unknown fields rejected.
- Secrets are **file references** (`{file: PATH}`). Environment refs require `security.allow_environment_secrets: true` (default false).
- `tools/labgen` writes unique ≥32-character legacy secrets, Argon2id PHC verifiers, a bearer token, and lab PKI. It does not print secret values into the manifest.
- `taclabd validate --config PATH` checks a candidate without publishing.
- `taclabd print-effective --config PATH --redacted` shows the compiled view.

### 3.1 ASCII / PAP (T89-SEC-002)

ASCII and PAP are **lab compatibility** methods. They are enabled in the reference example so device login and CHPASS can be exercised. They are not challenge-response and must not be treated as protected-network authentication.

To require challenge methods only, set the client (or intersection of global/listener/client/user) `allowed_methods` to `chap`, `mschapv1`, and/or `mschapv2`. Disallowed implemented types return **RESTART**, not a user-existence leak. See [ADR 0012](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md).

Login verifiers (Argon2id) are never used to compute CHAP/MS-CHAP. CHPASS updates only the runtime login verifier.

## 4. Legacy shared secrets

Policy keys live under `security.legacy_shared_secrets`:

| Key | 1.0 default / rule |
|---|---|
| `minimum_length_characters` | 16 (labgen uses ≥32) |
| `minimum_character_classes` | 3 |
| `reject_known_weak_values` | true |
| `warn_on_reuse` | true (process-local keyed HMAC; no fingerprint exported) |
| Rotation metadata | `last_rotated_at` + `rotation_interval` → `current` / `due_soon` / `overdue` |

Every enabled legacy client **must** have its own secret file. Cleartext legacy bodies (`TAC_PLUS_UNENCRYPTED_FLAG=1`) are rejected. Obfuscation is **not** confidentiality; run legacy TACACS only on an integrity-preserving management network.

Rotate by writing a new secret file and calling `config.reload` (or SIGHUP). Do not edit the old file in place if another process still holds it. UI/REST never return the secret.

## 5. Onboard a client

### Legacy device

1. Allocate a unique ≥32-character secret (`tools/labgen` or `openssl rand -base64 32`).
2. Add a `clients[]` entry: `match.transports: [legacy]`, `match.source_cidrs` for the **TCP peer TacLab will see** (see LAB_DEPLOYMENT §4.3 — published-port NAT often is not the device address).
3. Point the device at host:49 with that secret. Single-connect is optional per client.

### TLS 1.3 device (preferred)

1. Issue a client cert from the lab client CA (`tools/labcerts` / `labgen`).
2. `match.transports: [tls]`, `match.certificate.dns_sans` and/or `ip_sans`.
3. Point the device at host:300. Handshake is immediate; there is no upgrade and no fallback to port 49.
4. Revocation is `configured_crl`. A revoked serial fails the handshake and is re-checked on resume ([ADR 0005](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0005-ticket-lifetime.md)).
5. Wildcard server names must be a TACACS-only leftmost label (`*.tacacs.…`).

Ticket lifetime is `0` (disable resumption) or `168h` (Go’s cap). Other values are rejected.

## 6. Users, groups, and policy

- User `id` is the TACACS username (UsernameCasePreserved).
- Groups are flat. `services[]` never authorize a non-empty `cmd`. `command_rules[]` never decide a session request. Default deny on each evaluator.
- YAML `action: permit` is an alias of `permit_add`. REST/MCP writes use `permit_add` | `permit_replace` | `deny`.
- `default_command_action` must be `deny` or omitted.
- Explain a decision: UI Policy page or `POST /api/v1/policy/evaluate` (`policy:test`).

Golden personas: `administrators` session → priv-lvl 15; `readonly` `cmd=configure` → deny.

## 7. API tokens and the UI

- Bootstrap tokens come from files. Create more with `tokens:manage`; the value is shown **once**.
- Scopes are exact (`state:write` does not imply `tokens:manage`, `runtime:reset`, or `config:reload`).
- Browser: `POST /api/v1/session` exchanges `Authorization: Bearer` for an HttpOnly cookie. CSRF is required on cookie mutations. The UI never stores the bearer in `localStorage`.
- Reference Compose leaves HTTP admin without TLS (`cookie_secure` follows `listeners.http.tls.enabled`). Lab-only.

## 8. MCP clients (2026-07-28)

- `POST /mcp` only. GET/DELETE → 405.
- Required headers: `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, and `Mcp-Name` when applicable.
- Same bearer + scopes as REST. Lab static bearer is [ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md): **no** `.well-known/oauth-protected-resource`. Clients that require OAuth PRM will not complete discovery.
- Events: `subscriptions/listen` on `taclab://events/recent` notifies URI-only; pull bodies with `taclab.events.list`. Not a firehose.

Pinned official Go SDK is recorded but not imported ([ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)).

## 9. Reload, reset, export

| Action | How | Scope |
|---|---|---|
| Reload baseline | `SIGHUP` or `POST /api/v1/config/reload` | `config:reload` |
| Validate only | `POST /api/v1/config/validate` or `taclabd validate` | `state:write` (not a mutation) |
| Export redacted | `GET /api/v1/config/export` | `config:export` |
| Drop overlay | `POST /api/v1/runtime/reset` | `runtime:reset` |

File-watch reload is **off**. Invalid reload keeps the previous snapshot. There is no `config.import` in 1.0.

## 10. Logs, events, metrics

- Logs: stdout/stderr JSON. Secrets are typed holders and must not appear.
- Events: bounded ring (default 10_000). REST SSE `GET /api/v1/events/stream`; usernames/commands need `events:sensitive`.
- Metrics: default `127.0.0.1:9090`. Optional `observability.metrics.expose_on_admin: true` adds `/metrics` on 8080. pprof is off by default and is not on the admin listener.
- Accounting SUCCESS is returned only after the ring accepts the record.

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| Unknown client / no match | TCP peer vs `source_cidrs` (LAB §4.3). Events `client_id` is the match; `remote` is packet `rem_addr`. |
| Legacy ERROR after first packet | Wrong shared secret or length mismatch. |
| TLS handshake fails | Client cert CA, CRL, SAN, TLS 1.3 only, no 0-RTT. |
| ASCII on a challenge-only client | RESTART — start a new session with another type. |
| Reload rejected | `config.validate` problem details; previous revision still live. |
| UI stale after mutation | Watch revision / SSE `state.revision.changed`. |
| SSE/MCP listen drops at 30s | Handlers opt out of `write_timeout`; keep-alives required. `LAB-SSE-001`. |

Collect evidence without secrets: redacted export, `/api/v1/status`, `/api/v1/build`, events with `events:read` only, `make lab-test` report. Do not commit packet captures that contain shared secrets or passwords.

## 12. Upgrade and rollback

1. Record image digest and `taclabd version` / `/api/v1/build`.
2. Keep the baseline YAML and secret files (they are the rollback state).
3. Pull a new image tag or digest; `docker compose up -d`. Overlay is gone after recreate — expected.
4. Rollback: pin the previous digest and start the same YAML. Schema `1` is the 1.0 config version; unknown fields still fail closed.
5. Conformance rerun: `make check-registries` (includes `-release`) and `make lab-test` after protocol or TLS changes.

See [MAINTENANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MAINTENANCE.md) for cadence and deprecation.
