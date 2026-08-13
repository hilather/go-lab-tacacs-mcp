# TacLab quick start

Status: operator onboarding  
Last updated: 2026-08-13

Get a lab appliance running, log into the UI, and make one REST call and one MCP call. Protocol and schema details stay in [CONFIGURATION.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md) and [OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md). MCP depth is in [MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md).

TacLab is a **single-replica lab**. Runtime changes vanish on restart.

---

## 1. Prerequisites

| Need | Version |
|---|---|
| Linux host (or Linux VM) | Docker Engine + Compose v2 |
| Go (to run `labgen`) | **1.25.12** |
| Optional: Node | **22.14.0** if you rebuild the SPA |
| Host ports | 49, 300, 8080 — or use the high-port smoke overlay |

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
```

---

## 2. Generate the lab tree

Private keys, verifiers, and the API token are **not** in git.

```bash
go run ./tools/labgen deployments/compose
# equivalent: make lab-gen
```

That writes:

| Path | Role |
|---|---|
| `deployments/compose/config/taclab.yaml` | Baseline |
| `deployments/compose/secrets/api_admin_token` | Bootstrap bearer |
| `deployments/compose/secrets/PASSWORDS.txt` | Human copy (mode 0600) |
| `deployments/compose/certs-public/` | Server chain, client CA, CRL |
| `deployments/compose/pki/` | Lab PKI (keep private) |

Regenerate: `go run ./tools/labgen -force deployments/compose`.

---

## 3. Start

**Reference lab** (legacy 49 + TLS 300 + HTTP 8080):

```bash
docker compose -f deployments/compose/compose.yaml up -d --build
```

**TLS-only TACACS** (no host 49):

```bash
docker compose -f deployments/compose/compose.yaml \
  -f deployments/compose/compose.tls-only.yaml up -d --build
```

**No privileged ports:**

```bash
docker compose -f deployments/compose/compose.smoke.yaml up --build \
  --abort-on-container-exit --exit-code-from smoke
```

Wait for ready:

```bash
curl -sf http://127.0.0.1:8080/health/ready && echo ready
```

Compose uses `taclabd healthcheck --url http://127.0.0.1:8080/health/ready` inside the container.

---

## 4. Open the UI

1. Browse to `http://127.0.0.1:8080`.
2. Paste the contents of `deployments/compose/secrets/api_admin_token`.
3. The UI exchanges the bearer for an HttpOnly cookie (`POST /api/v1/session`). CSRF is required on cookie mutations.
4. You should see the dashboard: listeners, revision, users/groups/clients.

Do not store the raw bearer in the browser. The SPA does not use `localStorage` for it.

Hosted over HTTPS: see [MCP.md §4](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md) and set `cookie_secure` to follow TLS.

---

## 5. First REST call

```bash
TOKEN=$(tr -d '\n' < deployments/compose/secrets/api_admin_token)

curl -sS http://127.0.0.1:8080/api/v1/status \
  -H "Authorization: Bearer ${TOKEN}"
```

OpenAPI: `http://127.0.0.1:8080/api/openapi.json`.

---

## 6. First MCP call

```bash
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

Wire that URL into Claude, Cursor, or VS Code: [MCP.md §3](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md). Hosted / reverse-proxy: [MCP.md §4](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md).

There is **no** OAuth discovery document. Clients that require PRM will fail closed.

---

## 7. Point a device (optional)

| Transport | Host port | Identity |
|---|---|---|
| Legacy TACACS+ | 49 | Per-client shared secret file |
| Secure TACACS+ | 300 | Client cert from the lab client CA |

The TCP peer TacLab sees must match `clients[].match.source_cidrs`. Docker published ports often SNAT; generated YAML uses `0.0.0.0/0`. Narrow CIDRs belong on host-network or macvlan labs. Details: [LAB_DEPLOYMENT.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md) §4.3.

ASCII/PAP are enabled in the example for device login. Prefer `chap` / `mschapv1` / `mschapv2` on a protected network ([ADR 0012](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md)).

---

## 8. Prove it, then reset

```bash
make lab-test          # LAB-* suite on high ports
make cisco-lab         # optional; SKIP 0 without TACLAB_IOL_IMAGE
```

Drop the overlay without a restart:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/runtime/reset \
  -H "Authorization: Bearer ${TOKEN}"
```

A container recreate also wipes the overlay. That is expected.

---

## Next

- Operators: [OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md)
- Agents: [AGENTS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md) §1.1
- Fancy site: https://hilather.github.io/go-lab-tacacs-mcp/
