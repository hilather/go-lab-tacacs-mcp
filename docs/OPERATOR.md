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
| RADIUS access | 1812/udp | RFC 2865 PAP/CHAP plus opt-in EAP Identity/MD5 and MS-CHAPv1/v2. Access-Accept, Access-Reject, or Access-Challenge. Off unless a v2 profile enables it. |
| RADIUS accounting | 1813/udp | RFC 2866 Start/Stop/Interim/On/Off into the memory ring. Off unless a v2 profile enables it. |
| RADIUS/TLS (RadSec) | 2083/tcp | RFC 6614 TLS 1.3 mTLS stream of length-prefixed RADIUS packets. Off unless `listeners.radius.radsec.enabled` is true. Same opt-in methods as UDP (`eap` / `mschapv1` / `mschapv2`; omitted lists stay `[pap, chap]`). Not DTLS or RADIUS/1.1. |
| RADIUS dynauth (DAS) | 3799/udp | Optional RFC 5176 echo fixture. **Default off.** Index-only; does not kick a NAS. |
| HTTP admin | 8080/tcp | UI, `/api/v1`, `/mcp`, health |

Runtime overlay is **memory-only**. Restart or `runtime.reset` restores the YAML baseline. RADIUS retransmission cache, accounting journal, CoA session index, and the event ring go with the process. Do not put the overlay on a volume.

When both TACACS listeners are enabled, status/UI/logs show a **co-located lab topology** warning. That topology is a lab convenience ([ADR 0001](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0001-all-in-one-dual-listener-lab.md)). Production-like tests should use the TLS-only Compose overlay or separate hosts.

RADIUS/UDP uses MD5/HMAC-MD5 because the RFCs require it. Attributes other than User-Password travel in the clear. Keep 49, 300, **1812, 1813, 2083, and 3799 off the public internet** unless you intentionally publish RadSec behind the same posture as TACACS 300 ([ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md), [ADR 0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md)).

Inbound :3799 is an RFC 5176 test fixture; it does not kick a device. It only updates TacLab’s memory index. To disconnect a device, use Disconnect send.

### 1.1 Residual limits (honest)

Remaining RADIUS work is **in-memory**, **partial**, and **opt-in**. New listeners (`listeners.radius.dynamic_authorization` on UDP 3799 and `listeners.radius.radsec` on TCP 2083) default **off**. Ports **1812, 1813, 3799, and 2083 stay off the public internet**. Overlay, Challenge store, CoA session index, retransmission cache, accounting journal, and the event ring die with the process. `system.build.get` RADIUS `conformance_status` stays **`partial`**. There is no complete-RADIUS badge.

| Limit | What that means |
|---|---|
| Lab appliance | Single replica. No HA, no persistence adapter, no production AAA cluster. |
| Memory-only overlay | Create/shadow/tombstone users, groups, clients, tokens vanish on restart or `runtime.reset`. |
| Memory-only RADIUS | Challenge store, CoA session index, retransmission cache, accounting journal, and the event ring are process memory. Accounting-Response is sent only after the in-process ring accepts the record. Persistent accounting (`RAD-EXT-009`) is **cancelled** for this program ([ADR 0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md)). |
| UDP is the default RADIUS profile | Source-IP selects the UDP secret. Optional RadSec is a **TLS 1.3 stream** on TCP 2083 ([ADR 0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md)), default off — not “UDP plus TLS.” No DTLS, no RADIUS/1.1, no cleartext RADIUS/TCP. Shared secret is still required (do not default the informal string `radsec`). |
| Access-Challenge / EAP | Identity (type 1) + EAP-MD5 (type 4) terminate when `allowed_authentication_methods` includes `eap` (opt-in; omitted lists stay `[pap, chap]`). Other EAP types get generic EAP-Failure + Access-Reject. No PEAP/TLS/TTLS. `must_change_login` after a good MD5 is Access-Reject + the same generic EAP-Failure as a bad password. Program ADRs [0021](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0021-radius-access-challenge-state-gate.md) / [0022](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0022-radius-eap-identity-md5.md). |
| CoA / Disconnect | DAC originate (REST/MCP `radius:dynamic`) is the **only** path that kicks a NAS. Handle path needs Accounting-Start + Acct-Session-Id; access-only labs use explicit `client_id` + destination. Both paths sign with the client's **UDP** RADIUS secret. `lab-admin` does **not** get `radius:dynamic` by default. Optional inbound DAS (`listeners.radius.dynamic_authorization`, UDP 3799, default off) is an **RFC 5176 echo fixture**: it mutates TacLab’s memory index only and never forwards to a NAS, never tears down a TACACS session, and never sends UDP to the NAS. Add `dynamic_authorization` to the client RADIUS endpoint `roles` to accept inbound packets. `radius:dynamic` is not required for inbound. [ADR 0024](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0024-radius-coa-disconnect.md). |
| RADIUS MS-CHAP is opt-in / MD4-era | Add `mschapv1` / `mschapv2` to `allowed_authentication_methods`. Omitted lists stay `[pap, chap]`. Must-change is Access-Reject with no `MS-CHAP-Error`. [ADR 0023](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0023-radius-mschap-vsas.md). |
| Named `Cisco-AVPair` | Shipped as vendor 9 / vendor-type 1. Reply profiles accept `name: Cisco-AVPair` or raw `{vendor: 9, code: 1, value_hex}`. Evidence is independent fixtures ([ADR 0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md)). An IOL skip is not PASS. |
| Operator dictionaries | v2 `radius_dictionaries` are TacLab YAML, local absolute files, size-capped, fail-closed. Vendors 0/9/311 and `Cisco-AVPair` / `MS-CHAP-*` are reserved. Not FreeRADIUS `$INCLUDE`. Program ADR [0026](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0026-radius-operator-dictionaries.md). |
| User/group RADIUS rules (v2) | Optional `users[].radius_policy_id` / `groups[].radius_policy_id`. Walk is user → `effectiveGroups` → client → fallback → default deny ([ADR 0029](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0029-user-group-radius-policy-attachment.md)). v1 rejects the keys. |
| Proxying out | Not offered (`DEFERRED_MAY`, [ADR 0028](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0028-defer-radius-proxying.md)). |
| External `radclient` / IOL skip | A skip is **not** RADIUS PASS. |

Product, module, binary, and image names stay TacLab / `github.com/hilather/go-lab-tacacs-mcp` / `taclabd` / `ghcr.io/hilather/go-lab-tacacs-mcp` ([ADR 0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md)).

## 2. Install and start (Compose)

Prerequisites: Linux, Docker Compose v2, host ports 49/300/8080 (and UDP 1812/1813/3799 for combined or RADIUS-only; TCP 2083 if RadSec is enabled), or the high-port smoke overlay.

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
go run ./tools/labgen deployments/compose
docker compose -f deployments/compose/compose.yaml up -d --build
```

The default Compose baseline is **schema v1** (TACACS listeners only). Host 1812/1813/3799 are mapped; RADIUS sockets stay `enabled: false`. Inbound :3799 stays off until `listeners.radius.dynamic_authorization.enabled` is set.

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

RADIUS PAP uses the same login verifier. RADIUS CHAP and opt-in MS-CHAP (`mschapv1` / `mschapv2` on the RADIUS endpoint `allowed_authentication_methods`) use the same challenge secret. Omitted or empty RADIUS method lists stay `[pap, chap]`. Must-change after a good RADIUS MS-CHAP verify is Access-Reject with no `MS-CHAP-Error`.

### 3.2 RADIUS/UDP lab profile

This profile is useful for NAS login and accounting on a **controlled lab network**. It is not a substitute for RadSec.

What ships when a v2 file enables the sockets:

| Item | Behavior |
|---|---|
| Access | PAP, CHAP, and opt-in MS-CHAPv1/v2 / EAP (`mschapv1` / `mschapv2` / `eap` on `allowed_authentication_methods`; omitted lists stay `[pap, chap]`). Access-Accept, Access-Reject, or Access-Challenge (EAP Identity) after integrity + known client. Must-change is Access-Reject with no `MS-CHAP-Error`. |
| Message-Authenticator | Required on Access-Request by default. Always inserted first on Access-Accept, Access-Reject, and Accounting-Response. Accounting-Request MA is validate-if-present. |
| Policy | User `radius_policy_id`, then each `effectiveGroups` policy, then client `access_policy_id`, then optional `fallback_radius_policy_id`, then default deny. |
| Accounting | Start, Stop, Interim-Update, Accounting-On, Accounting-Off. SUCCESS on the wire only after the ring accepts the record. |
| Retransmission | Exact-response cache. Accounting also has a semantic journal that ignores Acct-Delay-Time. |
| Dictionary | Built-in IETF MVP (`builtin-mvp-1`). Optional v2 `radius_dictionaries` merge named vendor attributes as metadata (`source=operator:<id>`). Unknown wire attributes and VSAs stay raw. Named `Cisco-AVPair` (vendor 9 type 1) is implemented; an IOL skip is not PASS. |

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
6. Attach a user or group `radius_policy_id`, or a client `access_policy_id` (or rely on `fallback_radius_policy_id`). No match → Access-Reject.

`certificate_only` requires a TACACS TLS **or** RADIUS TLS endpoint. A RADIUS/UDP-only client cannot use `certificate_only` and still requires `source_cidrs`. A RadSec-only client may use `certificate_only` (TCP peer IP is not the Challenge bind). A TLS-only RADIUS client cannot originate CoA/Disconnect — DAC always uses the client’s **UDP** RADIUS endpoint secret and dest; add a UDP endpoint (and dest) if you need CoA.

### RADIUS RadSec NAS

Requires `schema_version: 2` and `listeners.radius.radsec.enabled: true` plus a `protocol: radius` / `transport: tls` endpoint. TLS 1.3 mTLS is required (`client_authentication: require_and_verify_certificate`). After handshake, TacLab selects the client from the peer certificate (and `source_cidrs` unless `certificate_only`). Point the NAS at host TCP **2083**. Do not describe this as encrypting UDP 1812.

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

Evaluation order is user `radius_policy_id`, then each group in `effectiveGroups` (same order as TACACS: user `group_ids`, then client `default_group_ids` not already present, then sort by ascending group `priority` then `id`), then client `access_policy_id`, then optional `fallback_radius_policy_id`, then default deny. Schema v2 only; v1 files reject `radius_policy_id`. REST/MCP omit keeps the current id; JSON `null` clears it. The Users and Groups editors expose a `radius_policy_id` select (generated types). Unknown ids fail the mutation.

Disabled users fail credentials before policy on Access-Request. `radius.policy.evaluate` still skips that user's policy and group_ids but walks client `default_group_ids`.

Match keys: `groups_any`, `method` (`password` canonical, `pap` alias stored as `password`, or `chap`), typed request attributes (`equals` / `present` / `absent`). No regex. Unknown attribute names fail compile.

Permit rules may list `reply_profiles`. Profiles concatenate in listed order; two `single` attributes of the same key fail compile. Deny rules may include only Access-Reject-legal attributes (`Reply-Message` in this profile). Named `Cisco-AVPair` (`shell:priv-lvl=15`) and raw `{vendor: 9, code: 1, value_hex}` encode to the same wire. Other named VSAs are not accepted.

Explain a RADIUS decision: UI RADIUS Policy page or `POST /api/v1/radius/policy:evaluate`. Drive the same `AuthenticateAccess` path as UDP with `POST /api/v1/radius/access:test` (`method.type` is `pap`, `chap`, `mschapv1`, `mschapv2`, or `eap`; passwords, MS-CHAP material, and EAP challenge/response are write-only and wiped). EAP Identity returns `access_challenge` with `state_present: true` only (no raw State, no EAP payload).

## 7. API tokens and the UI

- Bootstrap tokens come from files. Create more with `tokens:manage`; the value is shown **once**.
- Scopes are exact (`state:write` does not imply `tokens:manage`, `runtime:reset`, `config:reload`, or `radius:dynamic`). The example `lab-admin` token does not receive `radius:dynamic`.
- Browser: `POST /api/v1/session` exchanges `Authorization: Bearer` for an HttpOnly cookie. CSRF is required on cookie mutations. The UI never stores the bearer in `localStorage`.
- Reference Compose leaves HTTP admin without TLS (`cookie_secure` follows `listeners.http.tls.enabled`). Lab-only.
- RADIUS pages show an insecure-compatibility badge when Message-Authenticator is not required (UDP `allow_missing` only). Secret inputs are write-only and cleared after submit.
- RADIUS Sessions (`/radius-sessions`) lists the in-memory accounting index (`state:read`). CoA/Disconnect DAC buttons require `radius:dynamic`. Inbound :3799 is an RFC 5176 test fixture; it does not kick a device.
- RADIUS Auth Test methods are `pap`, `chap`, `mschapv1`, `mschapv2`, and `eap`. Challenge outcomes show `state_present` only.
- RADIUS Attributes lists dictionary metadata with a `source` column (`builtin` vs `operator:<id>`).

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

All mutating overlay calls need `expected_revision` (MCP) / `If-Match` (REST). Read `effective_revision` from the last `users.get` / `clients.get` / status first. CoA/Disconnect originate **rejects** `expected_revision` (not overlay CAS). Do not invent REST wrappers around MCP.

YAML field contract: [CONFIGURATION.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md) §7.10. ADR: [0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md). MCP setup: [MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md).

The reference Compose baseline is **not** flipped to must-change. Recipes use existing `lab-admin` / `lab-readonly` / `lab-switches`. Do not add a compose fixture user.

RADIUS advertised status stays **`partial`**. There is no Access-Challenge and no Microsoft Password-Expired VSA. Named `Cisco-AVPair` is available on reply profiles. `authentication.test` `status=must_change` is **not** a TACACS or RADIUS packet status.

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
| `taclab.radius.sessions.list` | `GET /api/v1/radius/sessions` | `state:read` |
| `taclab.radius.disconnect.send` | `POST /api/v1/radius/disconnect:send` | `radius:dynamic` |
| `taclab.radius.coa.send` | `POST /api/v1/radius/coa:send` | `radius:dynamic` |

### Overlay vs YAML (K16)

Applies to every must-change recipe below.

| How the flag was set | After `runtime.reset` / restart |
|---|---|
| YAML `must_change_login: true` | Flag **returns**; in-LOGIN / CHPASS new PHC is **gone**; old YAML verifier is back |
| YAML `must_change_enable: true` | Flag **returns**; in-ENABLE new PHC is **gone**; old YAML enable verifier is back |
| `taclab.users.update` flag only | Flag **gone**; baseline user restored |
| In-LOGIN / CHPASS / `OverrideLoginVerifier` | New login secret **gone** unless written into YAML |
| In-ENABLE / `OverrideEnableVerifier` | New enable secret **gone** unless written into YAML |

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

Expect `{ "status": "must_change" }`. Same body with `"method": "pap"` also `must_change` (identity lock). Do **not** copy this body with `"method": "chap"` or `"mschapv1"` / `"mschapv2"` — those methods require a challenge/response `data` blob, not `password`; missing `data` returns `status=error`, not `must_change`. Assert CHAP/MS-CHAP on the wire (FAIL + `Password change required`) after a good response.

RADIUS PAP assert (not the `authentication.test` shape — `method` is an object):

- Tool: `taclab.radius.access.test` · Scope: `policy:test`

```json
{
  "user_id": "lab-admin",
  "client_id": "lab-switches",
  "method": { "type": "pap", "password": "<current>" }
}
```

Expect `reason_code=reject_password_change_required` and `outcome=access_reject` with no extra attributes. RADIUS CHAP uses `{ "type": "chap", "id": …, "challenge": "<base64>", "response": "<base64>" }`, not `password`. This is **not** complete RADIUS and is not Access-Challenge.

#### 1c. MCP-only finish (no TACACS)

K16: the new login PHC and cleared flag live only in overlay.

Write a new Argon2id PHC first ([BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md) §4.1 **B. Durable PHC file**), mount it as a Compose secret, then rotate. `labgen` does **not** create this file. Do not invent a compose fixture user.

- Tool: `taclab.users.update` · Scope: `state:write`

```json
{
  "id": "lab-admin",
  "login": { "file": "/run/secrets/lab_admin_rotated_argon2id" },
  "expected_revision": 12
}
```

Flag clears unless the same patch sets `"must_change_login": true`. Overlay-only secret. `/run/secrets/lab_admin_argon2id` is the existing labgen login verifier — reuse it only to point back at the baseline file.

#### 1d. NAS / testclient finish

ASCII LOGIN extra GETPASS (`New Password: ` / `Retype New Password: `) if the client allows `ascii_chpass` (or `allowed_methods` is empty). That is a **lab/vendor extension**, not RFC 8907 LOGIN. Client-initiated CHPASS remains the RFC change-password path (prompts stay `Password: `). **Not MCP.**

If `ascii_chpass` is omitted from a non-empty allow-list: FAIL + `server_msg=Password change required`, no overlay mutation. MCP finish (1c) still works.

K16: published PHC + cleared flag are overlay-only. YAML-set `must_change_login: true` returns on `runtime.reset`.

### 2. Disable / re-enable

- Tool: `taclab.users.update` · Scope: `state:write`

```json
{ "id": "lab-readonly", "enabled": false, "expected_revision": 20 }
```

```json
{ "id": "lab-readonly", "enabled": true, "expected_revision": 21 }
```

Disabled + `must_change_login` stays uniform FAIL / empty `server_msg` (never `New Password: `).

### 3. Expire account (not password)

- Tool: `taclab.users.update` · Scope: `state:write`

`restrictions.valid_before` / `valid_after` expire the **identity**, not the password. Combined with `must_change_login` still looks like uniform FAIL.

`restrictions` is replace-as-a-struct (typed patch, not JSON Merge Patch). Sending only `valid_before` would drop baseline `lab-readonly` `client_ids`. Keep the current allow-list in the same object.

```json
{
  "id": "lab-readonly",
  "restrictions": {
    "client_ids": ["lab-switches", "secure-routers"],
    "valid_before": "2020-01-01T00:00:00Z"
  },
  "expected_revision": 22
}
```

Expect TACACS FAIL (uniform, empty `server_msg`) even if `must_change_login` is also true. Author: `user not valid at evaluation time`.

Not-yet-valid:

```json
{
  "id": "lab-readonly",
  "restrictions": {
    "client_ids": ["lab-switches", "secure-routers"],
    "valid_after": "2099-01-01T00:00:00Z"
  },
  "expected_revision": 23
}
```

### 5. Fixture must-change enable

K16: MCP-set `must_change_enable` is overlay-only. YAML-set flag survives `runtime.reset`; a published ENABLE PHC does not.

- Tool: `taclab.users.update` · Scope: `state:write`

```json
{ "id": "lab-admin", "must_change_enable": true, "expected_revision": 24 }
```

Assert: `taclab.authentication.test` `{ "user_id": "lab-admin", "method": "enable", "password": "<enable>" }` → `must_change`. MCP finish: `"enable": { "file": "/run/secrets/lab_admin_rotated_enable_argon2id" }` after writing a new PHC ([BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md) §4.1 **B**); the flag clears unless the same patch sets `"must_change_enable": true`. NAS / testclient finish is in-ENABLE GETPASS (TacLab/vendor extension, **not** RFC 8907 ENABLE). Not MCP.

`must_change_login` does not apply to ENABLE.

### 6. Clear / rotate secrets independently

- Tool: `taclab.users.update` · Scope: `state:write`

```json
{ "id": "lab-admin", "challenge": null, "expected_revision": 25 }
```

```json
{ "id": "lab-admin", "login": { "file": "/run/secrets/lab_admin_argon2id" }, "expected_revision": 26 }
```

JSON `null` / empty object clears (`OptionalSecret.Clear`). A non-nil login/enable patch **clears** the matching must-change flag unless the same patch sets the flag `true`. Clearing login while `must_change_login` is true is `invalid_argument`. Overlay-only (K16): reset restores the YAML verifier and YAML flag.

### 7. Move groups

- Tool: `taclab.users.update` · Scope: `state:write`

```json
{ "id": "lab-readonly", "group_ids": ["readonly"], "expected_revision": 27 }
```

### 8. Client restriction

- Tool: `taclab.users.update` · Scope: `state:write`

`restrictions` is replace-as-a-struct. This JSON sets the allow-list and clears any account window.

```json
{
  "id": "lab-readonly",
  "restrictions": { "client_ids": ["lab-switches"] },
  "expected_revision": 28
}
```

Restricted + `must_change_login` stays uniform FAIL / empty `server_msg`.

### 9. Tombstone / override / reveal

Create override:

- Tool: `taclab.users.create` · Scope: `state:write`

```json
{ "id": "lab-admin", "override": true, "display_name": "tmp", "expected_revision": 29 }
```

Reveal baseline (drop OVERRIDE, no tombstone):

- Tool: `taclab.users.delete` · Scope: `state:write`

```json
{ "id": "lab-admin", "tombstone": false, "expected_revision": 30 }
```

Tombstone baseline: `"tombstone": true`.

Reveal restores the YAML user, including YAML `must_change_*` (K16). Overlay flags and published PHCs vanish with the OVERRIDE.

### 10 / 13. Per-client `allowed_methods`

- Tool: `taclab.clients.update` · Scope: `state:write`

`authentication` is replace-as-a-struct. Include `default_service` so the lab client stays equivalent except for `allowed_methods`. Baseline `lab-switches` uses `login`.

Challenge-only NAS:

```json
{
  "id": "lab-switches",
  "authentication": {
    "allowed_methods": ["chap", "mschapv1", "mschapv2"],
    "default_service": "login"
  },
  "expected_revision": 30
}
```

ASCII / PAP / ENABLE / CHPASS **RESTART**. In-LOGIN change cannot run; MCP finish (1c) still works. CHAP/MS-CHAP + `must_change_login` still FAIL after a good response (identity lock).

Allow ASCII login but forbid NAS password mutation:

```json
{
  "id": "lab-switches",
  "authentication": {
    "allowed_methods": ["ascii", "pap"],
    "default_service": "login"
  },
  "expected_revision": 31
}
```

LOGIN + `must_change_login` → FAIL + `Password change required`, no overlay PHC. Empty `allowed_methods` means all implemented methods are allowed (including `ascii_chpass`).

### 12. Policy deny vs permit

`must_change_*` is **not** an authorization deny. `policy.evaluate` stays the QA tool for permit/deny fixtures.

- Tool: `taclab.policy.evaluate` · Scope: `policy:test`

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

- Tool: `taclab.runtime.reset` · Scope: `runtime:reset`

```json
{ "expected_revision": 32 }
```

Restores YAML, including YAML `must_change_*` and YAML verifiers (K16). MCP-set flags and published PHCs are gone. Source files are never rewritten.
