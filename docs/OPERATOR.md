# TacLab 1.0 operator guide

Status: 1.0 operator contract plus RADIUS/UDP lab profile  
Product: TacLab (`taclabd`)  
Last updated: 2026-08-16

This is the operator-facing 1.0 guide. Protocol and schema details stay in [CONFIGURATION.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md) and [LAB_DEPLOYMENT.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md). RADIUS conformance and deferred rows: [RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md).

**TacLab is a single-replica lab appliance, not a production AAA cluster.** RADIUS/UDP is a **controlled-network lab profile**. Do **not** treat enabled 1812/1813 sockets, a green ready check, or `PASS` MVP rows as complete RADIUS. `system.build.get` RADIUS `conformance_status` stays `partial`.

## 1. What you are running

| Surface | Host port | Role |
|---|---|---|
| Legacy TACACS+ | 49 → 4949/tcp | RFC 8907, per-client shared secret, obfuscation |
| Secure TACACS+ | 300 → 4300/tcp | RFC 9887 TLS 1.3 mTLS |
| RADIUS access | 1812/udp | RFC 2865 PAP/CHAP Access-Accept/Reject. Off unless a v2 profile enables it. |
| RADIUS accounting | 1813/udp | RFC 2866 Start/Stop/Interim/On/Off into the memory ring. Off unless a v2 profile enables it. |
| HTTP admin | 8080/tcp | UI, `/api/v1`, `/mcp`, health |

Runtime overlay is **memory-only**. Restart or `runtime.reset` restores the YAML baseline. RADIUS retransmission cache, accounting journal, and the event ring go with the process. Do not put the overlay on a volume.

When both TACACS listeners are enabled, status/UI/logs show a **co-located lab topology** warning. That topology is a lab convenience ([ADR 0001](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0001-all-in-one-dual-listener-lab.md)). Production-like tests should use the TLS-only Compose overlay or separate hosts.

RADIUS/UDP uses MD5/HMAC-MD5 because the RFCs require it. Attributes other than User-Password travel in the clear. Keep 49, 300, **1812, and 1813 off the public internet** ([ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md)).

### 1.1 Residual limits (honest)

| Limit | What that means |
|---|---|
| Lab appliance | Single replica. No HA, no persistence adapter, no production AAA cluster. |
| Memory-only overlay | Create/shadow/tombstone users, groups, clients, tokens vanish on restart or `runtime.reset`. |
| Memory-only RADIUS accounting | Accounting-Response is sent only after the in-process ring accepts the record. Restart loses the journal and the ring. |
| UDP controlled-network only | No RadSec, DTLS, RADIUS/TCP, or RADIUS/1.1. Source-IP selects the secret. |
| Deferred Access-Challenge | Types may exist; no provider ships (`R65-ACCESS-004` `DEFERRED_MAY`). |
| Deferred EAP | EAP-Message without a valid Message-Authenticator is discarded. There is no EAP method termination or pass-through. |
| Deferred CoA / Disconnect | RFC 5176 is out of this profile. |
| Deferred RADIUS MS-CHAP | TACACS MS-CHAP is not RADIUS VSA evidence. |
| Deferred named `Cisco-AVPair` | Raw Vendor-Specific framing is preserved. Named Cisco decoding waits on independent IOL vectors. |
| Built-in dictionary only | No operator dictionary files. Unknown attributes stay raw. |
| No user/group RADIUS rules | Client `access_policy_id`, optional `fallback_radius_policy_id`, then default deny. |
| External `radclient` / IOL skip | A skip is **not** RADIUS PASS. |

Product, module, binary, and image names stay TacLab / `github.com/hilather/go-lab-tacacs-mcp` / `taclabd` / `ghcr.io/hilather/go-lab-tacacs-mcp` ([ADR 0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md)).

## 2. Install and start (Compose)

Prerequisites: Linux, Docker Compose v2, host ports 49/300/8080 (and UDP 1812/1813 for combined or RADIUS-only), or the high-port smoke overlay.

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
go run ./tools/labgen deployments/compose
docker compose -f deployments/compose/compose.yaml up -d --build
```

The default Compose baseline is **schema v1** (TACACS listeners only). Host 1812/1813 are mapped; RADIUS sockets stay `enabled: false`.

Combined TACACS + RADIUS/UDP (schema v2, listeners on):

```bash
docker compose -f deployments/compose/compose.yaml \
  -f deployments/compose/compose.combined.yaml up -d --build
```

RADIUS-only (host 1812/1813/8080; no 49/300):

```bash
docker compose -f deployments/compose/compose.yaml \
  -f deployments/compose/compose.radius-only.yaml up -d --build
```

TLS-only TACACS (no host port 49, no legacy listener):

```bash
docker compose -f deployments/compose/compose.yaml \
  -f deployments/compose/compose.tls-only.yaml up -d --build
```

Health: `taclabd healthcheck --url http://127.0.0.1:8080/health/ready` (Compose uses this). Ready means snapshot + every `required` listener + at least one AAA listener (unless `server.admin_only: true`). Ready is **not** complete RADIUS.

Acceptance: `make lab-test` (high host ports, ephemeral PKI, LAB-* suite, plus combined / RADIUS-only / TACACS-only readiness).

## 3. Configuration and secrets

First-setup of users, groups, clients, tokens, and secret files: **[BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md)**. Schema: [CONFIGURATION.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md).

- Baseline: one YAML document, `schema_version: 1` or `2`, unknown fields rejected. v1 files keep working and compile to the same TACACS effective state; RADIUS listeners are synthesized `enabled: false`. RADIUS configuration requires `schema_version: 2`. Source files are never rewritten.
- Secrets are **file references** (`{file: PATH}`). Environment refs require `security.allow_environment_secrets: true` (default false).
- `tools/labgen` writes unique ≥32-character **legacy TACACS** and **distinct RADIUS** secrets, Argon2id PHC verifiers, a bearer token, and lab PKI. It does not print secret values into the manifest. Cross-purpose reuse of a TACACS secret as a RADIUS secret is a warning.
- `taclabd validate --config PATH` checks a candidate without publishing.

Checked-in templates (no secrets): [configs/lab.example.yaml](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/configs/lab.example.yaml) (v1) and [configs/lab.example.v2.yaml](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/configs/lab.example.v2.yaml) (combined).

### 3.1 ASCII / PAP (T89-SEC-002)

ASCII and PAP are **lab compatibility** methods. They are enabled in the reference example so device login and CHPASS can be exercised. They are not challenge-response and must not be treated as protected-network authentication.

To require challenge methods only, set the client (or intersection of global/listener/client/user) `allowed_methods` to `chap`, `mschapv1`, and/or `mschapv2`. Disallowed implemented types return **RESTART**, not a user-existence leak. See [ADR 0012](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md).

Login verifiers (Argon2id) are never used to compute CHAP/MS-CHAP. CHPASS updates only the runtime login verifier.

RADIUS PAP uses the same login verifier. RADIUS CHAP uses the same challenge secret. RADIUS MS-CHAP is **not** implemented.

### 3.2 RADIUS/UDP lab profile

This profile is useful for NAS login and accounting on a **controlled lab network**. It is not a substitute for RadSec.

What ships when a v2 file enables the sockets:

| Item | Behavior |
|---|---|
| Access | PAP and CHAP. Access-Accept or Access-Reject after integrity + known client. No Access-Challenge. |
| Message-Authenticator | Required on Access-Request by default. Always inserted first on Access-Accept, Access-Reject, and Accounting-Response. Accounting-Request MA is validate-if-present. |
| Policy | Client `access_policy_id`, then optional `fallback_radius_policy_id`, then default deny. |
| Accounting | Start, Stop, Interim-Update, Accounting-On, Accounting-Off. SUCCESS on the wire only after the ring accepts the record. |
| Retransmission | Exact-response cache. Accounting also has a semantic journal that ignores Acct-Delay-Time. |
| Dictionary | Built-in IETF MVP (`builtin-mvp-1`). Unknown attributes and VSAs stay raw. |

Weaker Access `message_authenticator: allow_missing` (or per-endpoint `require_message_authenticator: false`) is explicit, produces a validation warning, a `Status.Warnings` entry, and a UI “insecure RADIUS compatibility” badge. There is no global off switch.

Do not capture live RADIUS packets into git. User-Password, shared secrets, and most attributes are secret or PII.

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

### 4.1 RADIUS shared secrets

`security.radius_shared_secrets` is schema v2 only. It has the same shape as the legacy policy. When omitted, the effective RADIUS policy is a copy of the effective legacy policy.

- Purpose is `radius_shared_secret`. It cannot be assigned to a TACACS legacy holder.
- Source IP (not NAS-IP-Address / NAS-Identifier) selects the endpoint and secret.
- One RADIUS UDP endpoint per client in this profile; access and accounting share that secret and compile into separate role indexes.
- Rotate the same way as a legacy secret: new file, then `config.reload`.

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

### RADIUS NAS

Requires `schema_version: 2` and enabled `listeners.radius.access` (and `accounting` if the NAS sends it).

1. Allocate a **distinct** ≥32-character RADIUS secret (not the TACACS secret).
2. Add a RADIUS endpoint on the client (`protocol: radius`, `transport: udp`, `roles: [access, accounting]`). Set `match.source_cidrs` to the **UDP peer TacLab will see**.
3. Leave `require_message_authenticator: true` and `limit_proxy_state: true` unless you are deliberately exercising a warned compatibility client.
4. Point the NAS at host UDP 1812 (access) and 1813 (accounting). Configure the same secret. Enable Message-Authenticator on the NAS when the vendor supports it.
5. PAP needs a login verifier on the user. CHAP needs a challenge secret. Both methods must be listed on `allowed_authentication_methods`.
6. Attach `access_policy_id` (or rely on `fallback_radius_policy_id`). No match → Access-Reject.

`certificate_only` is invalid on a RADIUS-only client. RADIUS-only clients require `source_cidrs`.

## 6. Users, groups, and policy

How to add durable accounts and devices: [BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md).

- User `id` is the TACACS username **and** the RADIUS User-Name (UsernameCasePreserved). There is one user directory.
- Groups are flat. `services[]` never authorize a non-empty `cmd`. `command_rules[]` never decide a session request. Default deny on each evaluator.
- YAML `action: permit` is an alias of `permit_add`. REST/MCP writes use `permit_add` | `permit_replace` | `deny`.
- `default_command_action` must be `deny` or omitted.
- Explain a TACACS decision: UI Policy page or `POST /api/v1/policy/evaluate` (`policy:test`).
- Force next-login / next-enable change, disable, account window, groups, client restriction, and overlay wipe: [§14](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md#14-qa-user-lifecycle-recipes-mcp--rest).

Golden personas: `administrators` session → priv-lvl 15; `readonly` `cmd=configure` → deny.

### 6.1 RADIUS access policy

Evaluation order is client `access_policy_id`, then optional `fallback_radius_policy_id`, then default deny. There is no `users[].radius_policy_id` or `groups[].radius_rules`.

Match keys: `groups_any`, `method` (`password` canonical, `pap` alias stored as `password`, or `chap`), typed request attributes (`equals` / `present` / `absent`). No regex. Unknown attribute names fail compile.

Permit rules may list `reply_profiles`. Profiles concatenate in listed order; two `single` attributes of the same key fail compile. Deny rules may include only Access-Reject-legal attributes (`Reply-Message` in this profile). Named `Cisco-AVPair` is not accepted; raw VSA is `{vendor, code, value_hex}` only.

Explain a RADIUS decision: UI RADIUS Policy page or `POST /api/v1/radius/policy:evaluate`. Drive the same `AuthenticateAccess` path as UDP with `POST /api/v1/radius/access:test` (`method.type` is `pap` or `chap`; passwords are write-only and wiped).

## 7. API tokens and the UI

- Bootstrap tokens come from files. Create more with `tokens:manage`; the value is shown **once**.
- Scopes are exact (`state:write` does not imply `tokens:manage`, `runtime:reset`, or `config:reload`).
- Browser: `POST /api/v1/session` exchanges `Authorization: Bearer` for an HttpOnly cookie. CSRF is required on cookie mutations. The UI never stores the bearer in `localStorage`.
- Reference Compose leaves HTTP admin without TLS (`cookie_secure` follows `listeners.http.tls.enabled`). Lab-only.
- RADIUS pages show an insecure-compatibility badge when Message-Authenticator is not required. Secret inputs are write-only and cleared after submit.

## 8. MCP clients (2026-07-28)

Local desktop clients and hosted/remote agents: **[MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md)** (both setups, client JSON, reverse proxy, curl). First boot: [QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md).

- `POST /mcp` only. GET/DELETE → 405.
- Required headers: `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, and `Mcp-Name` when applicable.
- Same bearer + scopes as REST. Lab static bearer is [ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md): **no** `.well-known/oauth-protected-resource`. Clients that require OAuth PRM will not complete discovery.
- Events: `subscriptions/listen` on `taclab://events/recent` notifies URI-only; pull bodies with `taclab.events.list`. Not a firehose.
- RADIUS diagnostics are `taclab.radius.access.test`, `taclab.radius.policy.evaluate`, and `taclab.radius.attributes.list`. Missing tool ⇒ missing scope, not a missing feature.
- Copy-paste QA recipes (must-change fixture / assert / rotate and existing user workflows): [§14](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md#14-qa-user-lifecycle-recipes-mcp--rest). Do not invent `taclab.qa.*` tools.

MCP Streamable HTTP uses `github.com/modelcontextprotocol/go-sdk` v1.7.0 ([ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)). Lab static bearer is unchanged ([ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)).

## 9. Reload, reset, export

| Action | How | Scope |
|---|---|---|
| Reload baseline | `SIGHUP` or `POST /api/v1/config/reload` | `config:reload` |
| Validate only | `POST /api/v1/config/validate` or `taclabd validate` | `state:write` (not a mutation) |
| Export redacted | `GET /api/v1/config/export` | `config:export` |
| Drop overlay | `POST /api/v1/runtime/reset` | `runtime:reset` |

`runtime.reset` restores the YAML baseline, including YAML `must_change_*` flags and YAML verifiers. MCP/REST-set flags and published in-LOGIN / CHPASS / in-ENABLE PHCs do **not** survive (K16). See [§14](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md#14-qa-user-lifecycle-recipes-mcp--rest) recipe 14.

File-watch reload is **off**. Invalid reload keeps the previous snapshot. There is no `config.import` in 1.0.

`config.export` **never** emits v2 YAML for a v1 source unless you pass the explicit convert flag `normalize=true` (REST query `?normalize=true`, MCP argument `normalize`; default false). A v2 source exports as v2. Do not auto-upgrade a v1 file on disk.

## 10. Logs, events, metrics

- Logs: stdout/stderr JSON. Secrets are typed holders and must not appear.
- Events: bounded ring (default 10_000). REST SSE `GET /api/v1/events/stream`; usernames/commands/`acct_session_id` need `events:sensitive`. Optional filters `protocol`, `listener_role`, `packet_code`, and `outcome` AND with categories.
- Metrics: default `127.0.0.1:9090`. Optional `observability.metrics.expose_on_admin: true` adds `/metrics` on 8080. pprof is off by default and is not on the admin listener. RADIUS scrapes use `taclab_protocol_*` / `taclab_radius_*` with closed `protocol`, `role`, `reason_code`, `outcome` labels — never `client_id`, User-Name, or peer IPs.
- Accounting SUCCESS is returned only after the ring accepts the record. If the ring rejects a RADIUS accounting record, there is **no** Accounting-Response.

Useful RADIUS scrapes (not a pager contract): `rate(taclab_protocol_discards_total{protocol="radius"}[5m])`, `taclab_radius_cache_saturations_total`, `taclab_radius_journal_saturations_total`.

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| Unknown client / no match | TCP or UDP peer vs `source_cidrs` (LAB §4.3). Events `client_id` is the match; `remote` is packet `rem_addr`. |
| Legacy ERROR after first packet | Wrong shared secret or length mismatch. |
| TLS handshake fails | Client cert CA, CRL, SAN, TLS 1.3 only, no 0-RTT. |
| ASCII on a challenge-only client | RESTART — start a new session with another type. |
| RADIUS silent discard (no reply) | Unknown/ambiguous source, malformed length, invalid code for the role, invalid Accounting-Request Authenticator, missing/invalid Message-Authenticator, EAP-Message without MA, Proxy-State without MA when `limit_proxy_state`, unknown Acct-Status-Type, or `drop_overload`. Watch `taclab_protocol_discards_total` `reason`. |
| RADIUS Access-Reject | Unknown user / bad password / disabled (`reject_bad_credentials` — no user-existence leak), conflicting PAP+CHAP, CHAP-Password length ≠ 17, method not allowed, or policy deny / default deny. |
| RADIUS Access-Reject `reject_password_change_required` | User has `must_change_login`. Identity lock after a **good** PAP/CHAP. No Access-Challenge, no extra attributes. MCP finish is `taclab.users.update` secret rotate ([§14](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md#14-qa-user-lifecycle-recipes-mcp--rest)). |
| TACACS FAIL `Password change required` | Good password + `must_change_login` on PAP/CHAP/MS-CHAP, or ASCII LOGIN when the client omits `ascii_chpass`. Wrong password stays empty `server_msg`. |
| RADIUS NAS retries forever | Secret mismatch (invalid authenticator is silent). Compatibility client without MA against `required`. Published-port NAT changing source IP. |
| Insecure RADIUS compatibility badge | Endpoint or listener inherited `allow_missing`. Restore `required` unless you are deliberately testing a warned client. |
| Accounting-Response missing | Ring rejected the record (`internal_error`, no wire SUCCESS). Check ring capacity. |
| Duplicate accounting events | Semantic journal saturation (`taclab_radius_journal_saturations_total`) or ambiguous identity (no Acct-Session-Id and no NAS-IP/NAS-Identifier) under the per-minute sample budget. |
| Reload rejected | `config.validate` problem details; previous revision still live. Mixed v1/v2 listener keys fail closed. |
| UI stale after mutation | Watch revision / SSE `state.revision.changed`. |
| SSE/MCP listen drops at 30s | Handlers opt out of `write_timeout`; keep-alives required. `LAB-SSE-001`. |

Collect evidence without secrets: redacted export, `/api/v1/status`, `/api/v1/build`, events with `events:read` only, `make lab-test` report. Do not commit packet captures that contain shared secrets or passwords. Do not tell peers to disable Message-Authenticator checking.

## 12. Upgrade and rollback

1. Record image digest and `taclabd version` / `/api/v1/build`.
2. Keep the baseline YAML **and** secret files (they are the rollback state). If you adopt schema v2, **keep a v1 copy**. Old binaries cannot parse v2.
3. Pull a new image tag or digest; `docker compose up -d`. Overlay, RADIUS cache, accounting journal, and the event ring are gone after recreate — expected.
4. Existing v1 deployments: binary upgrade only. No YAML edits. RADIUS listeners stay disabled until you write v2 and enable them.
5. Rollback: pin the previous digest and start the **same schema version** that binary understands. Never point an old 1.0 binary at a v2 file.
6. Failed v2 reload keeps the previous snapshot. `runtime.reset` drops overlay only; it does not rewrite the baseline file.
7. Conformance rerun: `make check-registries` (includes `-release` for TACACS) and `make lab-test` after protocol or TLS changes. RADIUS `-release` completeness is **not** claimed.

See [MAINTENANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MAINTENANCE.md) for cadence and deprecation.

## 13. Schema v1 → v2 migration

v1 remains a supported source format ([ADR 0017](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0017-config-schema-v2-with-v1-migration.md)).

```text
strict v1 YAML
  -> decode with the v1 raw model
  -> in-memory migration to named listener structs
  -> RADIUS listeners synthesized enabled: false
  -> compile the same TACACS effective state
```

| Goal | What to do |
|---|---|
| Keep TACACS-only after a binary upgrade | Leave `schema_version: 1`. No file edits. |
| Add RADIUS | Write a v2 file (`listeners.tacacs.*` / `listeners.radius.*`, `endpoints[]`, RADIUS secret file). Validate, then reload or recreate. |
| Preview v2 YAML from a running v1 source | `GET /api/v1/config/export?normalize=true` (or MCP `normalize: true`). Review the redacted YAML. **Copy it yourself** into a new file. The server never rewrites the source. |
| Export a v1 source as v1 | `GET /api/v1/config/export` with `normalize` omitted or false. |
| Mixed keys | Fatal. v1 must not contain `listeners.radius` / `listeners.tacacs`. v2 must not contain `listeners.legacy_tacacs` / `listeners.secure_tacacs`. |

Validate before reload:

```bash
taclabd validate --config deployments/compose/config/taclab.yaml
# or POST /api/v1/config/validate
```

Rollback is “keep the v1 file and the previous image digest.” Do not expect an old binary to load v2.

## 14. QA user-lifecycle recipes (MCP / REST)

MCP owns **fixture + assert + admin rotate**. GETPASS / CONTINUE is **NAS / `internal/tacacs/testclient` only**. Hosted MCP cannot speak ports 49/300. Do **not** invent `taclab.qa.*` tools. Use the existing `taclab.*` operations (same typed requests as REST).

All mutating calls need `expected_revision` (MCP) / `If-Match` (REST). Read `effective_revision` from the last `users.get` / `clients.get` / status first. Do not invent REST wrappers around MCP.

YAML field contract: [CONFIGURATION.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md) §7.10. ADR: [0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md). MCP setup: [MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md).

The reference Compose baseline is **not** flipped to must-change. Recipes use existing `lab-admin` / `lab-readonly` / `lab-switches`. Do not add a compose fixture user.

RADIUS advertised status stays **`partial`**. There is no Access-Challenge, no Microsoft Password-Expired VSA, and no named `Cisco-AVPair`. `authentication.test` `status=must_change` is **not** a TACACS or RADIUS packet status.

| MCP tool | REST | Scope |
|---|---|---|
| `taclab.users.update` | `PATCH /api/v1/users/{id}` | `state:write` |
| `taclab.users.get` | `GET /api/v1/users/{id}` | `state:read` |
| `taclab.users.create` | `POST /api/v1/users` | `state:write` |
| `taclab.users.delete` | `DELETE /api/v1/users/{id}` | `state:write` |
| `taclab.authentication.test` | `POST /api/v1/authentication/test` | `policy:test` |
| `taclab.clients.update` | `PATCH /api/v1/clients/{id}` | `state:write` |
| `taclab.policy.evaluate` | `POST /api/v1/policy/evaluate` | `policy:test` |
| `taclab.runtime.reset` | `POST /api/v1/runtime/reset` | `runtime:reset` |
| `taclab.radius.access.test` | `POST /api/v1/radius/access:test` | `policy:test` |

### Overlay vs YAML (K16)

Say this in every must-change recipe.

| How the flag was set | After `runtime.reset` / restart |
|---|---|
| YAML `must_change_login: true` | Flag **returns**; in-LOGIN / CHPASS new PHC is **gone**; old YAML verifier is back |
| `taclab.users.update` flag only | Flag **gone**; baseline user restored |
| In-LOGIN / CHPASS / `OverrideLoginVerifier` | New secret **gone** unless written into YAML |

YAML-set flag = durable lab fixture. REST/MCP-set flag = overlay-only. After a NAS change, keep the new secret across reset only by writing it into YAML (or accept overlay-only). The YAML baseline is never rewritten.

### 1. Fixture must-change (overlay)

K16: this flag is overlay-only. `runtime.reset` / restart restores the YAML user (flag false unless YAML set it).

- Tool: `taclab.users.update` · Scope: `state:write`

```json
{ "id": "lab-admin", "must_change_login": true, "expected_revision": 11 }
```

`must_change_login` is an **identity lock** on all login-class methods after a successful verify (ASCII, PAP, CHAP, MS-CHAP, RADIUS access). It does **not** apply to ENABLE. It is not a `restrictions` field.

#### 1b. Assert fixture (does not CONTINUE)

- Tool: `taclab.authentication.test` · Scope: `policy:test`

```json
{ "user_id": "lab-admin", "method": "ascii", "password": "<current>" }
```

Expect `{ "status": "must_change" }`. Same body with `"method": "pap"` or `"chap"` also `must_change` (identity lock). Wire for PAP/CHAP is FAIL, not a `must_change` packet. RADIUS assert is `taclab.radius.access.test` → `reason_code=reject_password_change_required` (Access-Reject, no extra attributes).

#### 1c. MCP-only finish (no TACACS)

K16: the new login PHC and cleared flag live only in overlay.

```json
{
  "id": "lab-admin",
  "login": { "file": "/run/secrets/new_login_argon2id" },
  "expected_revision": 12
}
```

Flag clears unless the same patch sets `"must_change_login": true`. Overlay-only secret.

#### 1d. NAS / testclient finish

ASCII LOGIN extra GETPASS (`New Password: ` / `Retype New Password: `) if the client allows `ascii_chpass` (or `allowed_methods` is empty). That is a **lab/vendor extension**, not RFC 8907 LOGIN. Client-initiated CHPASS remains the RFC change-password path (prompts stay `Password: `). **Not MCP.**

If `ascii_chpass` is omitted from a non-empty allow-list: FAIL + `server_msg=Password change required`, no overlay mutation. MCP finish (1c) still works.

K16: published PHC + cleared flag are overlay-only. YAML-set `must_change_login: true` returns on `runtime.reset`.

### 2. Disable / re-enable

- Tool: `taclab.users.update` · `state:write`

```json
{ "id": "lab-readonly", "enabled": false, "expected_revision": 20 }
```

```json
{ "id": "lab-readonly", "enabled": true, "expected_revision": 21 }
```

Disabled + `must_change_login` stays uniform FAIL / empty `server_msg` (never `New Password: `).

### 3. Expire account (not password)

`restrictions.valid_before` / `valid_after` expire the **identity**, not the password. Combined with `must_change_login` still looks like uniform FAIL.

```json
{
  "id": "lab-readonly",
  "restrictions": { "valid_before": "2020-01-01T00:00:00Z" },
  "expected_revision": 22
}
```

Expect TACACS FAIL (uniform, empty `server_msg`) even if `must_change_login` is also true. Author: `user not valid at evaluation time`.

Not-yet-valid:

```json
{
  "id": "lab-readonly",
  "restrictions": { "valid_after": "2099-01-01T00:00:00Z" },
  "expected_revision": 23
}
```

### 5. Fixture must-change enable

K16: MCP-set `must_change_enable` is overlay-only. YAML-set flag survives `runtime.reset`; a published ENABLE PHC does not.

```json
{ "id": "lab-admin", "must_change_enable": true, "expected_revision": 24 }
```

Assert: `taclab.authentication.test` `{ "user_id": "lab-admin", "method": "enable", "password": "<enable>" }` → `must_change`. MCP finish: `"enable": { "file": "..." }` (clears the flag unless the same patch sets `"must_change_enable": true`). NAS / testclient finish is in-ENABLE GETPASS (TacLab/vendor extension, **not** RFC 8907 ENABLE). Not MCP.

`must_change_login` does not apply to ENABLE.

### 6. Clear / rotate secrets independently

```json
{ "id": "lab-admin", "challenge": null, "expected_revision": 25 }
```

```json
{ "id": "lab-admin", "login": { "file": "/run/secrets/lab_admin_argon2id" }, "expected_revision": 26 }
```

JSON `null` / empty object clears (`OptionalSecret.Clear`). A non-nil login/enable patch **clears** the matching must-change flag unless the same patch sets the flag `true`. Clearing login while `must_change_login` is true is `invalid_argument`. Overlay-only (K16): reset restores the YAML verifier and YAML flag.

### 7. Move groups

```json
{ "id": "lab-readonly", "group_ids": ["readonly"], "expected_revision": 27 }
```

### 8. Client restriction

```json
{
  "id": "lab-readonly",
  "restrictions": { "client_ids": ["lab-switches"] },
  "expected_revision": 28
}
```

Restricted + `must_change_login` stays uniform FAIL / empty `server_msg`.

### 9. Tombstone / override / reveal

Create override: `taclab.users.create` `{ "id": "lab-admin", "override": true, "display_name": "tmp", "expected_revision": N }` · `state:write`.

Reveal baseline (drop OVERRIDE, no tombstone): `taclab.users.delete`

```json
{ "id": "lab-admin", "tombstone": false, "expected_revision": 29 }
```

Tombstone baseline: `"tombstone": true`.

Reveal restores the YAML user, including YAML `must_change_*` (K16). Overlay flags and published PHCs vanish with the OVERRIDE.

### 10 / 13. Per-client `allowed_methods`

- Tool: `taclab.clients.update` · `state:write`

Challenge-only NAS:

```json
{
  "id": "lab-switches",
  "authentication": { "allowed_methods": ["chap", "mschapv1", "mschapv2"] },
  "expected_revision": 30
}
```

ASCII / PAP / ENABLE / CHPASS **RESTART**. In-LOGIN change cannot run; MCP finish (1c) still works. CHAP/MS-CHAP + `must_change_login` still FAIL after a good response (identity lock).

Allow ASCII login but forbid NAS password mutation:

```json
{
  "id": "lab-switches",
  "authentication": { "allowed_methods": ["ascii", "pap"] },
  "expected_revision": 31
}
```

LOGIN + `must_change_login` → FAIL + `Password change required`, no overlay PHC. Empty `allowed_methods` means all implemented methods are allowed (including `ascii_chpass`).

### 12. Policy deny vs permit

`must_change_*` is **not** an authorization deny. `policy.evaluate` stays the QA tool for permit/deny fixtures.

- Tool: `taclab.policy.evaluate` · `policy:test`

```json
{
  "user_id": "lab-readonly",
  "client_id": "lab-switches",
  "service": "shell",
  "cmd": "configure",
  "cmd_args": []
}
```

Fields are `EvaluatePolicyRequest` (`user_id`, `client_id`, `service`, `cmd`, `cmd_args`).

### 14. Full overlay wipe

- Tool: `taclab.runtime.reset` · `runtime:reset`

```json
{ "expected_revision": 32 }
```

Restores YAML, including YAML `must_change_*` and YAML verifiers (K16). MCP-set flags and published PHCs are gone. Source files are never rewritten.
