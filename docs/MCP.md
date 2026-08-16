# MCP setup — local and remote

Status: operator and agent contract  
MCP baseline: 2026-07-28  
Last updated: 2026-08-16

TacLab exposes administrative operations as an MCP server on the **same HTTP listener** as REST and the UI. REST and MCP share one operation registry, one bearer verifier, and one exact-match scope matrix. MCP never proxies REST.

This page is the setup and usage guide. The parity policy lives in [API_PARITY.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/API_PARITY.md). The exemption from OAuth Protected Resource Metadata is [ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md). The transport is the official Go SDK ([ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)).

| | Local | Remote (hosted) |
|---|---|---|
| Typical URL | `http://127.0.0.1:8080/mcp` | `https://taclab.example.invalid/mcp` |
| Who terminates TLS | Nobody (lab HTTP) | Reverse proxy or `listeners.http.tls` |
| Token | File on this machine | Distributed out of band |
| Origin | Usually absent | Restrict `api.mcp.allowed_origins` if browsers call `/mcp` |
| Devices | Optional | Point NAS gear at host 49 / 300 (TACACS) and 1812 / 1813 (RADIUS/UDP, when enabled) separately |

Both paths use **identical** headers, tools, resources, and scopes.

---

## 1. Contract (both setups)

| Item | Rule |
|---|---|
| Method / path | `POST /mcp` only. `GET` and `DELETE` return **405**. |
| Protocol header | `MCP-Protocol-Version: 2026-07-28` — exclusive. Other versions → `400` / `-32022`. Opt out with `api.mcp.allow_legacy_clients: true` (default `false`): the header check is skipped and the SDK negotiates the version during `initialize`, so older-generation clients (MCP gateways/proxies) can connect. `subscriptions/listen` always requires the pinned version. |
| Method header | `Mcp-Method` required. Must match the JSON-RPC `method` when both are present. |
| Name header | `Mcp-Name` required for `tools/call`, `resources/read`, and `prompts/get`. **ASCII only.** |
| Accept | `application/json, text/event-stream`. The adapter fills a missing Accept header. |
| Auth | `Authorization: Bearer <token>` |
| WWW-Authenticate | `Bearer realm="taclab"` on 401. This is **not** OAuth discovery. |
| OAuth PRM | **Not served.** `.well-known/oauth-protected-resource` is absent. |
| Session | Stateless. `Mcp-Session-Id` and `Last-Event-ID` are ignored. |
| Body limit | Default 2 MiB (`listeners.http.max_request_body_bytes`). |
| `_meta` | Required on listen (and expected by 2026-07-28 clients): `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`. |

Frozen RPC surface:

- `server/discover`
- `tools/list` / `tools/call`
- `resources/list` / `resources/read`
- `subscriptions/listen` (URI-only notify on `taclab://events/recent`)

`tools/list` and `resources/list` are **scope-filtered**. A missing scope is `permission_denied`, not an unknown tool.

Official MRTR elicitation is out of 1.0. Clients that insist on OAuth PRM will not complete discovery. That is an advertised 1.0 limit, not a bug.

---

## 2. Token

Lab mode is `api.mode: lab_static_bearer`.

1. After `go run ./tools/labgen deployments/compose` (or `make lab-gen`), read:

   ```bash
   TOKEN=$(tr -d '\n' < deployments/compose/secrets/api_admin_token)
   ```

   labgen also writes `deployments/compose/secrets/PASSWORDS.txt` (mode `0600`) for humans. Do not commit either file.

2. Create more tokens with `tokens:manage` (`POST /api/v1/tokens` or `taclab.tokens.create`). The value is returned **once**.

3. Scopes are exact. `state:write` does not grant `tokens:manage`, `config:reload`, or `runtime:reset`.

Bootstrap scopes in the reference lab:

`state:read` · `state:write` · `config:reload` · `config:export` · `policy:test` · `events:read` · `tokens:manage` · `runtime:reset`

Add `events:sensitive` if the client must see usernames and commands.

---

## 3. Local setup

Use this when the MCP client and `taclabd` share a host (or you SSH-tunnel `:8080`).

### 3.1 Start TacLab

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
go run ./tools/labgen deployments/compose
docker compose -f deployments/compose/compose.yaml up -d --build
curl -sf http://127.0.0.1:8080/health/ready
```

High ports without privileged 49/300: `deployments/compose/compose.smoke.yaml` or `make lab-test`.

From a binary, after labgen has written the tree:

```bash
make build
./bin/taclabd serve --config deployments/compose/config/taclab.yaml
```

The process prints `listening http …` and `ready`. MCP is on that HTTP listener.

### 3.2 Client snippets

Replace the bearer with the file contents. Do not paste tokens into git, issues, or chat logs.

**Claude Desktop / Claude Code** (`claude_desktop_config.json` or project MCP config):

```json
{
  "mcpServers": {
    "taclab": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_ME",
        "MCP-Protocol-Version": "2026-07-28"
      }
    }
  }
}
```

**Cursor** (`.cursor/mcp.json` or user MCP settings):

```json
{
  "mcpServers": {
    "taclab": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_ME",
        "MCP-Protocol-Version": "2026-07-28"
      }
    }
  }
}
```

**VS Code Copilot** (`.vscode/mcp.json`):

```json
{
  "servers": {
    "taclab": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer ${input:taclab-token}",
        "MCP-Protocol-Version": "2026-07-28"
      }
    }
  },
  "inputs": [
    {
      "id": "taclab-token",
      "type": "promptString",
      "description": "TacLab lab bearer",
      "password": true
    }
  ]
}
```

If the client only supports stdio MCP, it cannot speak TacLab 1.0. TacLab is **Streamable HTTP**, not a local subprocess.

### 3.3 curl smoke (local)

```bash
TOKEN=$(tr -d '\n' < deployments/compose/secrets/api_admin_token)

curl -sS http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/list" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {
      "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
      }
    }
  }'
```

Call a tool (status):

```bash
curl -sS http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/call" \
  -H "Mcp-Name: taclab.system.status.get" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "taclab.system.status.get",
      "arguments": {},
      "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
      }
    }
  }'
```

### 3.4 SSH tunnel (local client, remote process)

If `taclabd` already runs on a lab VM but you want a desktop MCP client:

```bash
ssh -N -L 8080:127.0.0.1:8080 user@lab-host
```

Then use the **local** URL and the **remote** token. This is still the local-client / remote-process pattern; you are not exposing MCP to the internet.

---

## 4. Remote / hosted setup

Use this when operators and agents reach TacLab over the network. TacLab remains a **single-replica lab appliance**. HTTPS in front does not make it a production AAA cluster.

### 4.1 Deploy the appliance

On the lab host:

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
go run ./tools/labgen deployments/compose
docker compose -f deployments/compose/compose.yaml up -d --build
```

Or pin a release image (do not use `latest`):

```bash
docker pull ghcr.io/hilather/go-lab-tacacs-mcp:1.0.0
```

and point Compose `image:` at that tag or digest. Variants: `1.0.0-ubuntu`, `1.0.0-rocky`.

TLS-only TACACS (no host port 49):

```bash
docker compose -f deployments/compose/compose.yaml \
  -f deployments/compose/compose.tls-only.yaml up -d --build
```

### 4.2 Network split

| Port | Audience | Advice |
|---|---|---|
| 49 | Legacy devices | Lab VLAN / management VRF only |
| 300 | TLS 1.3 devices | Same; do not publish to the internet |
| 8080 | Operators, REST, MCP, UI | Put behind HTTPS; do not publish plaintext |
| 9090 | Metrics | Loopback or monitor network. Off the admin listener by default |

Client match uses the **TCP peer TacLab sees**, not `X-Forwarded-For` and not TACACS `rem_addr`. Published Docker ports often SNAT the device. Generated lab YAML uses `0.0.0.0/0` for that reason. See [LAB_DEPLOYMENT.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md) §4.3.

### 4.3 HTTPS in front (recommended)

Terminate TLS at Caddy or nginx. Forward **only POST** `/mcp` plus the UI and `/api/v1` if operators need them. Preserve `Authorization`. Do not strip `MCP-Protocol-Version`, `Mcp-Method`, or `Mcp-Name`.

Set `listeners.http.trusted_proxy_cidrs` to the proxy addresses if you rely on forwarded client IPs for HTTP (this still does **not** affect TACACS client match).

If you enable `listeners.http.tls` on taclabd itself, `cookie_secure` follows that unless overridden.

**Caddy** (`Caddyfile`):

```caddy
taclab.example.invalid {
    encode gzip
    reverse_proxy 127.0.0.1:8080
}
```

**nginx**:

```nginx
server {
    listen 443 ssl http2;
    server_name taclab.example.invalid;

    # ssl_certificate / ssl_certificate_key …

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header MCP-Protocol-Version $http_mcp_protocol_version;
        proxy_set_header Mcp-Method $http_mcp_method;
        proxy_set_header Mcp-Name $http_mcp_name;
        proxy_set_header Origin $http_origin;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;          # SSE / listen
        proxy_read_timeout 3600s;     # listen outlives write_timeout
    }
}
```

`subscriptions/listen` and REST SSE opt out of TacLab `write_timeout` and send keep-alives. The **proxy** must not buffer or 30-second-kill those streams (`LAB-SSE-001`).

### 4.4 Origin policy

```yaml
api:
  mcp:
    allowed_origins: []     # empty: same-host UI origin is still allowed
    require_origin: false   # true → reject requests with no Origin
```

- Non-browser MCP clients usually send **no** Origin. Leave `require_origin: false`.
- Browser-hosted MCP UIs must be listed in `allowed_origins` (exact match).
- A present Origin that is neither allowed nor `http(s)://<Host>` is **403**.

### 4.5 Remote client config

Same JSON as local, different URL:

```json
{
  "mcpServers": {
    "taclab": {
      "url": "https://taclab.example.invalid/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_ME",
        "MCP-Protocol-Version": "2026-07-28"
      }
    }
  }
}
```

Distribute the bearer via your secret store, not via the public site and not as a query parameter.

### 4.6 Remote curl

```bash
curl -sS https://taclab.example.invalid/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/list" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

### 4.7 Checklist before inviting agents

- [ ] `/health/ready` succeeds through the public HTTPS name
- [ ] `POST /mcp` with a bad token is 401 (not 200, not HTML)
- [ ] `GET /mcp` is 405
- [ ] `tools/list` returns only tools allowed by the token scopes
- [ ] Proxy does not drop custom MCP headers
- [ ] Listen / SSE survive longer than 30 seconds
- [ ] Token is not in the image, Compose file, or git history
- [ ] Ports 49 and 300 are not open to the internet

---

## 5. Tools, resources, and listen

See the catalog in the [root README](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/README.md) and the generated inventory ([docs/generated/api-parity.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/api-parity.md)).

Mutations accept `expected_revision` (MCP) / `If-Match` (REST) and optional `idempotency_key` / `Idempotency-Key`. Structured MCP content is the operation result **without** the REST envelope.

`subscriptions/listen` notifies `{ uri, subscriptionId }` only. Pull bodies with `taclab.events.list`. It is not a firehose.

---

## 6. Troubleshooting

| Symptom | Check |
|---|---|
| Client stuck on OAuth / `.well-known` | Expected. ADR 0010. Use a client that can send a static bearer. |
| 401 | Missing/wrong `Authorization`. Token revoked or file not the one labgen wrote. |
| 403 origin | `Origin` not in `allowed_origins` and not same-host. |
| 400 / `-32022` | Protocol version is not `2026-07-28`. |
| 400 / `-32020` | Header / `_meta` mismatch. |
| 405 | Used GET/DELETE. Streamable HTTP is POST only. |
| Empty `tools/list` | Token lacks `state:read` (and other scopes). |
| Listen drops at ~30s | Proxy `proxy_read_timeout` / buffering. TacLab itself keeps the stream. |
| Domain not-found | JSON-RPC `-32000` (not `-32601` — the SDK would rewrite that). |

Collect evidence without secrets: redacted `config.export`, `system.status.get`, events with `events:read` only.

---

## 7. Agent instructions (copy into a session)

```text
You are operating TacLab, a lab TACACS+ appliance with MCP 2026-07-28
Streamable HTTP at POST /mcp.

1. Do not look for OAuth PRM. Send Authorization: Bearer <token>.
2. Send MCP-Protocol-Version: 2026-07-28 on every request.
3. Use tools/list, then call taclab.* tools. Never invent REST paths
   as a substitute for a missing tool — if a tool is absent, the
   token lacks the scope.
4. Mutating tools: pass expected_revision from the last read.
5. Secrets never appear in list/get/export/events. Token values appear
   only on taclab.tokens.create.
6. subscriptions/listen is URI-only; pull events with taclab.events.list.
7. Runtime overlay is memory-only. runtime.reset or restart restores YAML.
8. This is a lab. Do not treat dual listeners or static bearers as a
   production AAA design.
9. Force next-login change with taclab.users.update must_change_login /
   must_change_enable (top-level bools, not restrictions). Assert with
   taclab.authentication.test status must_change. RADIUS surfaces
   reject_password_change_required. No taclab.qa.* tools.
```

Operator walkthrough for non-MCP tasks: [OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md). First boot: [QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md).
