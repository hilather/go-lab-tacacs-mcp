<p align="center">
  <img alt="TacLab" src="https://img.shields.io/badge/TacLab-taclabd-1a1f24?style=for-the-badge&labelColor=c8893a&color=1a1f24" />
</p>

<h1 align="center">TacLab</h1>

<p align="center"><strong>The all-in-one TACACS+ lab appliance that agents can drive.</strong></p>

<p align="center">
  RFC&nbsp;8907 · RFC&nbsp;9887 TLS&nbsp;1.3 · RADIUS/UDP lab profile · MCP&nbsp;2026-07-28 · REST/MCP parity · embedded operator UI
</p>

<p align="center">
  <a href="https://github.com/hilather/go-lab-tacacs-mcp/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/hilather/go-lab-tacacs-mcp/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://github.com/hilather/go-lab-tacacs-mcp/blob/main/LICENSE"><img alt="Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-c8893a?labelColor=1a1f24" /></a>
  <a href="https://github.com/hilather/go-lab-tacacs-mcp/releases"><img alt="Release" src="https://img.shields.io/github/v/release/hilather/go-lab-tacacs-mcp?color=2bb3a8&labelColor=1a1f24" /></a>
  <img alt="Go 1.25.13" src="https://img.shields.io/badge/Go-1.25.13-00ADD8?labelColor=1a1f24" />
  <img alt="MCP 2026-07-28" src="https://img.shields.io/badge/MCP-2026--07--28-2bb3a8?labelColor=1a1f24" />
</p>

<p align="center">
  <a href="https://hilather.github.io/go-lab-tacacs-mcp/"><strong>Project site</strong></a>
  ·
  <a href="https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md"><strong>Quick start</strong></a>
  ·
  <a href="https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md"><strong>Users & groups</strong></a>
  ·
  <a href="https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md"><strong>MCP local & remote</strong></a>
  ·
  <a href="https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md"><strong>Agent setup</strong></a>
</p>

---

TacLab is a **single-process lab appliance** for device administration experiments. One Go binary — **`taclabd`** — speaks legacy TACACS+, secure TACACS+ over TLS 1.3, and an optional **RADIUS/UDP lab profile**, then exposes the **same** administrative operations through REST, MCP, and an embedded React UI.

The repository is `go-lab-tacacs-mcp`. The product is **TacLab**. This checkout is the **1.0 lab appliance**, not a production AAA cluster. Runtime state is memory-only: restart or `runtime.reset` restores the YAML baseline. RADIUS/UDP is a **controlled-network lab profile** — do **not** advertise complete RADIUS. Residual limits: [operator guide](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md) §1.1.

| | |
|---|---|
| Go module | `github.com/hilather/go-lab-tacacs-mcp` |
| Images | `ghcr.io/hilather/go-lab-tacacs-mcp` — `:<tag>` distroless, `:<tag>-ubuntu`, `:<tag>-rocky` |
| License | Apache-2.0 |
| Toolchain | Go **1.25.13** (module `go 1.25.0`) · Node.js **22.14.0** |
| Protocol pins | RFC 8907 · RFC 9887 · RADIUS/UDP lab profile (RFC 2865/2866/2869/3579 MA / 5080) · MCP **2026-07-28** |
| MCP SDK | `github.com/modelcontextprotocol/go-sdk` **v1.7.0** ([ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)) |
| Auth | Lab static bearer on REST and MCP ([ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)) — **no** OAuth PRM |

RFC 8907 and RFC 9887 **server `MUST` / `MUST NOT` / `PROJECT MUST`** rows are `PASS` or `N/A_RFC_DEPRECATED` with evidence IDs in [testdata/conformance](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/testdata/conformance/rfc8907.yaml). `make check-registries` includes the `-release` gate. Device-family completeness is **not** claimed.

```mermaid
flowchart LR
  subgraph devices [Lab devices]
    L[Legacy NAS]
    T[TLS 1.3 NAS]
    U[RADIUS NAS]
  end
  subgraph operators [Operators and agents]
    B[Browser UI]
    R[REST client]
    M[MCP client]
  end
  subgraph taclabd [taclabd]
    LEG[":49 legacy TACACS+"]
    TLS[":300 TACACS+ TLS"]
    RAD[":1812 / :1813 RADIUS/UDP"]
    HTTP[":8080 UI / REST / MCP"]
    OPS[Operation registry]
    AAA[AAA + policy + ring]
  end
  L --> LEG
  T --> TLS
  U --> RAD
  B --> HTTP
  R --> HTTP
  M --> HTTP
  LEG --> AAA
  TLS --> AAA
  RAD --> AAA
  HTTP --> OPS --> AAA
```

---

## Features

### TACACS+ AAA

| Capability | What 1.0 actually does |
|---|---|
| ASCII LOGIN, PAP | Lab-compatibility methods ([ADR 0012](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md)). Not challenge-response. |
| CHAP, MS-CHAP v1/v2 | Challenge secrets are separate from Argon2id login verifiers ([ADR 0002](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0002-password-kdf.md)). |
| ENABLE | Privilege escalation; type ignored as specified. |
| ASCII CHPASS | Updates the **runtime** login verifier only. |
| Service authorization | `services[]` never authorize a non-empty `cmd`. Default deny. |
| Command authorization | `command_rules[]` never decide a session request. `default_command_action` is deny. |
| Accounting | RFC 8907 flag table: START, STOP, WATCHDOG, WATCHDOG+update. SUCCESS only after the event ring accepts the record. |
| Dual listeners | Legacy TCP 49 and TLS 1.3 mTLS 300, no upgrade path, no fallback ([ADR 0001](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0001-all-in-one-dual-listener-lab.md)). |
| Legacy secrets | Per-client files, ≥16-char policy (labgen uses ≥32), complexity, reuse warning, rotation status. Obfuscation is **not** confidentiality. |
| Secure TACACS+ | TLS 1.3 only, mTLS, configured CRL, resume re-checks revocation, no 0-RTT, `UNENCRYPTED` required inside TLS. |

### RADIUS/UDP lab profile (not complete RADIUS)

Optional sockets. Default YAML stays `enabled: false`. Schema v2 required. Controlled lab network only ([ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md)).

| Capability | What this tree actually does |
|---|---|
| Access | PAP and CHAP → Access-Accept or Access-Reject. No Access-Challenge. |
| Accounting | Start / Stop / Interim / On / Off into the **memory** ring. SUCCESS only after the ring accepts. |
| Integrity | Message-Authenticator required on Access by default; always first on responses. |
| Policy | User `radius_policy_id`, then `effectiveGroups`, then client `access_policy_id`, then optional fallback, then default deny. Schema v2 only; v1 rejects the keys. |
| Dictionary | Built-in IETF MVP plus named `Cisco-AVPair` (vendor 9 type 1). Unknown attributes stay raw. Operator dictionaries are fail-closed TacLab YAML. |
| Deferred | EAP termination, CoA/Disconnect, RadSec/DTLS, RADIUS MS-CHAP, custom dictionaries, persistent accounting. |

`system.build.get` RADIUS `conformance_status` stays `partial`. Matrix: [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md). Operator guide: [docs/OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md).

### Admin surfaces (one registry)

| Surface | Binding | Notes |
|---|---|---|
| Embedded SPA | `:8080/` | Users, groups, clients, tokens, policy explain, auth test, events, config. |
| REST | `/api/v1/*` | OpenAPI at `/api/openapi.json`. Cookie session is REST-only. |
| MCP | `POST /mcp` | Streamable HTTP, official Go SDK. Same handlers as REST. |
| Events | REST SSE · MCP listen | REST streams bodies. MCP notifies `taclab://events/recent` (URI only); pull with `taclab.events.list`. |
| Health | `/health/live`, `/health/ready` | REST-only probes. |
| Metrics | `127.0.0.1:9090` | Optional `/metrics` on 8080. pprof off by default. |

REST/MCP equivalence is enforced by `internal/api/parity`. Adapters never call each other.

### Lab appliance

- YAML baseline + file-referenced secrets. Unknown fields fail closed.
- Memory overlay: create/shadow/tombstone users, groups, clients, tokens at runtime.
- Restart or `runtime.reset` returns the mounted baseline.
- Non-root, read-only rootfs, `cap_drop: ALL` Compose reference.
- Optional Cisco IOL lab via Containerlab (`make cisco-lab`) — **skips** without an operator-built image.
- Required software peer: in-tree `internal/tacacs/testclient` (separate codec). See [interop notes](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/INTEROP.md).
- Metrics and governors live under `internal/observability`. pprof is off by default.

---

## Quick start

**Need 90 seconds?** → [docs/QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md)

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
go run ./tools/labgen deployments/compose
docker compose -f deployments/compose/compose.yaml up -d --build
```

Then open `http://127.0.0.1:8080`. The bootstrap bearer is the file `deployments/compose/secrets/api_admin_token` (labgen also writes `secrets/PASSWORDS.txt` mode `0600`). Exchange it in the UI; the SPA never stores the raw token in `localStorage`.

| Profile | Command |
|---|---|
| Dual TACACS listener (host 49 / 300 / 8080; RADIUS mapped, off in v1 YAML) | `docker compose -f deployments/compose/compose.yaml up -d --build` |
| Combined TACACS + RADIUS/UDP (also 1812/1813) | add `-f deployments/compose/compose.combined.yaml` |
| RADIUS-only (1812/1813/8080; no 49/300) | add `-f deployments/compose/compose.radius-only.yaml` |
| TLS-only TACACS (no legacy 49) | add `-f deployments/compose/compose.tls-only.yaml` |
| High-port smoke (no privileged ports, no generated PKI) | `docker compose -f deployments/compose/compose.smoke.yaml up --build --abort-on-container-exit --exit-code-from smoke` |
| Container acceptance | `make lab-test` |
| Optional Cisco IOL | `make cisco-lab` |

From a built binary:

```bash
make build
./bin/taclabd serve --config deployments/compose/config/taclab.yaml
./bin/taclabd healthcheck --url http://127.0.0.1:8080/health/ready
```

`serve` requires `--config`. Reload is **SIGHUP** or `POST /api/v1/config/reload`. File-watch reload is off.

---

## Configure the baseline (users, groups, clients)

Durable AAA state is **files**, not a database. Full walkthrough: [docs/BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md).

| File | What you put there |
|---|---|
| `deployments/compose/config/taclab.yaml` | `users[]`, `groups[]`, `clients[]`, `api.bootstrap_tokens[]`, listeners, policy |
| `deployments/compose/secrets/*` | Argon2id PHC verifiers, challenge secrets, legacy TACACS secrets, API bearer |
| `deployments/compose/compose.yaml` | Bind-mounts the YAML and maps each secret to `/run/secrets/<name>` |

`labgen` writes two groups (`administrators` priv-lvl 15, `readonly` priv-lvl 1), three users (`lab-admin`, `lab-readonly`, `lab-disabled`), two clients (`lab-switches` legacy, `secure-routers` TLS), and one bootstrap token. User `id` **is** the TACACS username.

- **Durable:** edit YAML + secret files, `taclabd validate`, recreate Compose if you added a secret, then `config.reload`.
- **Ephemeral:** UI / REST / MCP create users, groups, clients, tokens. Gone on restart or `runtime.reset`.

Do not inline secret values in YAML. ASCII/PAP need a login verifier; CHAP/MS-CHAP need a separate challenge secret; ENABLE needs its own verifier.

---

## MCP — local and remote

**Full guide (headers, client JSON, reverse proxy, scopes, curl):** [docs/MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md)

Both setups use the **same** contract:

| Item | Value |
|---|---|
| Endpoint | `POST /mcp` only (GET/DELETE → 405) |
| Protocol | `MCP-Protocol-Version: 2026-07-28` |
| Auth | `Authorization: Bearer <token>` — lab static bearer, **not** OAuth |
| Discovery | No `.well-known/oauth-protected-resource` ([ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)) |
| Accept | `application/json, text/event-stream` |

### Local MCP (same host as `taclabd`)

After the Compose lab is up:

```json
{
  "mcpServers": {
    "taclab": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_WITH_FILE_CONTENTS",
        "MCP-Protocol-Version": "2026-07-28"
      }
    }
  }
}
```

Point Cursor, Claude Desktop / Claude Code, VS Code Copilot, or any **2026-07-28 Streamable HTTP** client at that URL. Clients that **require OAuth PRM** will not complete discovery — that is intentional.

### Remote MCP (hosted appliance)

1. Deploy Compose on the lab host (or pull `ghcr.io/hilather/go-lab-tacacs-mcp:<tag>`).
2. Put `:8080` behind HTTPS (Caddy / nginx). Enable `listeners.http.tls` **or** terminate TLS at the proxy and set `trusted_proxy_cidrs`.
3. Distribute the bearer **out of band**. Never put it in the image or in git.
4. Point the MCP client at `https://taclab.example.invalid/mcp` with the same headers as local.
5. Restrict `api.mcp.allowed_origins` if a browser origin will call `/mcp`. Non-browser clients typically send no `Origin`.
6. Expose **49 / 300 only to lab devices**. Expose **443 / 8080 only to operators**.

See [docs/MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md) for Caddy and nginx snippets, origin policy, and a complete `tools/call` example.

---

## REST and MCP catalog

Every `PARITY_REQUIRED` operation is the same handler. Live inventory: [docs/generated/api-parity.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/api-parity.md). Policy: [docs/API_PARITY.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/API_PARITY.md).

### Tools and resources

| Operation | Scope | REST | MCP tool | Resource |
|---|---|---|---|---|
| Status | `state:read` | `GET /api/v1/status` | `taclab.system.status.get` | `taclab://status` |
| Build | `state:read` | `GET /api/v1/build` | `taclab.system.build.get` | `taclab://build` |
| Effective config | `state:read` | `GET /api/v1/config/effective` | `taclab.config.effective.get` | `taclab://config/effective` |
| Validate config | `state:write` | `POST /api/v1/config/validate` | `taclab.config.validate` | — |
| Reload | `config:reload` | `POST /api/v1/config/reload` | `taclab.config.reload` | — |
| Export | `config:export` | `GET /api/v1/config/export` | `taclab.config.export` | — |
| Runtime reset | `runtime:reset` | `POST /api/v1/runtime/reset` | `taclab.runtime.reset` | — |
| Users CRUD | `state:read` / `state:write` | `/api/v1/users` | `taclab.users.*` | `taclab://users` |
| Groups CRUD | `state:read` / `state:write` | `/api/v1/groups` | `taclab.groups.*` | `taclab://groups` |
| Clients CRUD | `state:read` / `state:write` | `/api/v1/clients` | `taclab.clients.*` | `taclab://clients` |
| Tokens | `tokens:manage` | `/api/v1/tokens` | `taclab.tokens.*` | — |
| Policy explain | `policy:test` | `POST /api/v1/policy/evaluate` | `taclab.policy.evaluate` | — |
| Auth test | `policy:test` | `POST /api/v1/authentication/test` | `taclab.authentication.test` | — |
| RADIUS access test | `policy:test` | `POST /api/v1/radius/access:test` | `taclab.radius.access.test` | — |
| RADIUS policy explain | `policy:test` | `POST /api/v1/radius/policy:evaluate` | `taclab.radius.policy.evaluate` | — |
| RADIUS attributes | `state:read` | `GET /api/v1/radius/attributes` | `taclab.radius.attributes.list` | `taclab://radius/attributes` |
| Events page | `events:read` | `GET /api/v1/events` | `taclab.events.list` | `taclab://events/recent` |
| Event stream | `events:read` | `GET /api/v1/events/stream` (SSE) | `subscriptions/listen` | notify URI only |

Usernames and commands in events also need `events:sensitive`.

### Protocol-only (not parity)

| Binding | Why |
|---|---|
| `GET /health/live`, `GET /health/ready` | Infrastructure probes |
| `GET /api/openapi.json` | Describes REST |
| `POST/DELETE /api/v1/session` | HttpOnly cookie + CSRF |
| `server/discover`, `tools/list`, `resources/list` | MCP discovery (scope-filtered) |
| `notifications/list_changed` | MCP tools/resources list-changed |

### Exact scopes (no hierarchy)

`state:write` does **not** imply `tokens:manage`, `runtime:reset`, or `config:reload`.

`state:read` · `state:write` · `config:reload` · `config:export` · `policy:test` · `events:read` · `events:sensitive` · `tokens:manage` · `runtime:reset`

---

## Agent setup

Coding agents working in this tree: read **[AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md)** first. Section 1.1 is the first-time environment. Short path:

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
# Go 1.25.13 and Node 22.14.0 — see go.mod toolchain and .nvmrc
make test
make check-registries
make lab-gen
```

Before changing protocol, REST, MCP, UI, or config: [docs/CANONICAL_DESIGN.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md) wins on conflict. [docs/ARCHITECTURE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md) is the package boundary contract. Do not implement MCP by proxying REST.

---

## Documentation map

Every contract linked from this page, with what it covers.

### Start here

| Document | What it is |
|---|---|
| [Quick start](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md) | Clone → generate → Compose → UI login → first REST and MCP calls |
| [Baseline state](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md) | Configure users, groups, clients, tokens, secrets, listeners |
| [MCP local & remote](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md) | Streamable HTTP, client configs, hosted TLS, origins, curl |
| [Operator guide (1.0)](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md) | Install, secrets, onboard TACACS and RADIUS clients, v1/v2 migration, residual limits, troubleshooting |
| [Lab deployment](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md) | Image contract, Compose, PKI, LAB-* scenarios, source-IP fidelity |
| [Configuration](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md) | YAML schema, listeners, overlay, secret refs |
| [Project site](https://hilather.github.io/go-lab-tacacs-mcp/) | Fancy landing page for the same material |

### Contracts (read before changing code)

| Document | What it is |
|---|---|
| [Canonical implementation design](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md) | **Execution source of truth** |
| [Agent rules](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) | Mandatory engineering, parity, CI-watch, release rules |
| [Source packet README](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/README.md) | Historical packet index and reading order |
| [Product design (packet)](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/DESIGN.md) | Packet product/system design |
| [Architecture](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md) | Package boundaries and dependency direction |
| [TACACS conformance](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TACACS_CONFORMANCE.md) | RFC 8907 / 9887 matrix |
| [RADIUS conformance](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) | RFC 2865/2866/2869/3579/5080 lab-profile checklist — **not** complete RADIUS |
| [RADIUS remaining work](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md) | In-memory remaining-work program (ADRs 0020–0029; not shipped until impl PRs) |
| [REST/MCP API parity](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/API_PARITY.md) | Parity dispositions and operation contract |
| [Testing and benchmarks](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TESTING_AND_BENCHMARKS.md) | Race, fuzz, benches, freeze policy |
| [Threat model](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/THREAT_MODEL.md) | Trust boundaries and abuse cases |
| [Tasks](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TASKS.md) | Phased backlog and acceptance gates |
| [References](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/REFERENCES.md) | RFCs, MCP spec, SDK, Go, Compose |

### Decisions

| ADR | Decision |
|---|---|
| [0001](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0001-all-in-one-dual-listener-lab.md) | Dual-listener lab topology |
| [0002](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0002-password-kdf.md) | Argon2id KDF and username profile |
| [0003](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0003-cached-information.md) | RFC 7924 Cached Information not implemented |
| [0004](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0004-tls13-cipher-policy.md) | TLS 1.3 cipher lists rejected |
| [0005](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0005-ticket-lifetime.md) | Ticket lifetime `0` or `168h` only |
| [0006](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0006-external-psk-rpk.md) | External PSK / raw public keys deferred |
| [0007](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0007-codec-approach.md) | Internal TACACS codec |
| [0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md) | Lab static bearer vs MCP OAuth PRM |
| [0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md) | Official MCP Go SDK |
| [0012](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md) | ASCII/PAP enablement warning |
| [0013](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0013-add-radius-to-existing-taclab-process.md) | RADIUS in the existing `taclabd` process |
| [0014](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0014-neutral-aaa-contract-and-protocol-taxonomy.md) | Neutral AAA contracts; TACACS wrappers stay |
| [0015](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0015-radius-codec-attribute-and-dictionary-boundary.md) | RADIUS codec/attribute/dictionary boundary |
| [0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md) | UDP controlled-network profile; Access-Challenge deferred |
| [0017](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0017-config-schema-v2-with-v1-migration.md) | Schema v2; `config.export` never emits v2 for a v1 source without `normalize=true` |
| [0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md) | Keep TacLab / `taclabd` / module / image names |
| [0019](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0019-force-password-change.md) | Force login-class lock; lab/vendor in-LOGIN GETPASS (not RFC LOGIN) |
| [0020](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0020-in-memory-radius-remaining-work-program.md) | In-memory remaining-work charter; persist cancelled; `conformance_status` stays `partial` |
| [0021](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0021-radius-access-challenge-state-gate.md) | Access-Challenge state gate (not advertised until testclient evidence) |
| [0022](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0022-radius-eap-identity-md5.md) | EAP Identity + MD5 only; must-change stays Access-Reject + generic EAP-Failure |
| [0023](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0023-radius-mschap-vsas.md) | RADIUS MS-CHAP VSAs; independent RADIUS vectors; methods opt-in |
| [0024](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0024-radius-coa-disconnect.md) | DAC CoA uses UDP endpoint secret; inbound DAS is echo fixture only |
| [0025](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0025-radius-radsec-tls13-first-slice.md) | RadSec TLS 1.3 TCP 2083 first slice; DTLS/1.1 deferred |
| [0026](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0026-radius-operator-dictionaries.md) | Fail-closed operator dictionary YAML; reserve vendors 0/9/311 |
| [0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md) | Named `Cisco-AVPair` via independent fixtures; supersedes ADR 0015 IOL gate |
| [0028](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0028-defer-radius-proxying.md) | RADIUS proxying / realm routing `DEFERRED_MAY` |
| [0029](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0029-user-group-radius-policy-attachment.md) | v2 user/group `radius_policy_id`; walk user → groups → client → fallback → deny |

### Operator / maintainer

| Document | What it is |
|---|---|
| [Developer workflow](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/DEVELOPER.md) | Generate, registries, frontend, release evidence |
| [Interop notes](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/INTEROP.md) | Software peer vs optional IOL skip |
| [Maintenance policy](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MAINTENANCE.md) | Supported versions and release cadence |
| [Changelog](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CHANGELOG.md) | Operator-facing deltas |
| [Benchmark budgets](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/benchmarks/budgets.yaml) | Latency / alloc freeze |
| [Generated toolchain](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/toolchain.md) | Pinned toolchain record |
| [Generated operation inventory](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/api-parity.md) | Live REST/MCP matrix |
| [Generated conformance inventory](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/conformance.md) | Live RFC row report |
| [Contributing](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CONTRIBUTING.md) | Toolchains and `make ci` |
| [Security policy](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/SECURITY.md) | Vulnerability reporting |
| [Code of conduct](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CODE_OF_CONDUCT.md) | Conduct |
| [License](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/LICENSE) | Apache-2.0 |

On conflict, the canonical design wins over copied packet documents.

---

## Prerequisites

- Go **1.25.13** (`go.mod` `toolchain`)
- Node.js **22.14.0** and npm **10.9.x** (`.nvmrc`, `web/package.json`)
- `make`
- Docker Compose v2 for the reference lab

## Local checks

```bash
make test
make test-race
make web-test
make web-e2e
make lint
make secrets
make check-registries
make check-generated
make docs-check
make build
./bin/taclabd -h
make lab-test
```

`make bench` runs hot-path benches under `internal/tacacs`, `internal/policy`, `internal/state`, and `internal/aaa`. Argon2id KDF benches live under `internal/credentials` and are excluded from that target.

`make ci` is the local equivalent of the GitHub Actions merge gate (without `govulncheck` network install unless you run `make vuln`).

---

<p align="center">
  <em>Lab appliance. Dual TACACS listeners. Optional RADIUS/UDP profile. One registry. Agents welcome. Not complete RADIUS.</em>
</p>
