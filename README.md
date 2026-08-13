# TacLab (`taclabd`)

TacLab is an all-in-one Go TACACS+ / MCP lab appliance. The repository name is `go-lab-tacacs-mcp`; the product name is **TacLab** and the binary is **`taclabd`**.

| Item | Value |
|---|---|
| Go module | `github.com/hilather/go-lab-tacacs-mcp` |
| Image | `ghcr.io/hilather/go-lab-tacacs-mcp` |
| License | Apache-2.0 |
| Go | 1.24.5 |
| Node.js | 22.14.0 |
| MCP specification | 2026-07-28 |
| Official MCP Go SDK baseline | `github.com/modelcontextprotocol/go-sdk v1.7.0` (recorded; not a compile-time dependency of this skeleton) |

This checkout implements ASCII LOGIN, PAP, CHAP, MS-CHAP v1/v2, ENABLE, and ASCII CHPASS, plus one service rule, one command rule, the full RFC 8907 accounting flag table, a bounded event ring with cursor reads and stdout JSON, `status` / `policy.evaluate` / `events.list` on REST and MCP, a distinct secure TACACS TLS 1.3 listener (`internal/tacacs/tls`), and `internal/tacacs/testclient` `DialTLS` (DNS-ID/IP-ID/SRV-ID, UNENCRYPTED, no 0-RTT, no legacy fallback). `taclabd serve --config` binds enabled TACACS listeners (legacy and/or TLS) and, when enabled, the HTTP admin listener. TLS-only is supported. It does **not** implement the admin UI or complete TACACS+. Do not describe it as a complete TACACS+ server.

High-port Compose smoke (no privileged 49/300):

```bash
docker compose -f deployments/compose/compose.smoke.yaml config
docker compose -f deployments/compose/compose.smoke.yaml up --build --abort-on-container-exit --exit-code-from smoke
```

## Documents

- [Canonical implementation design](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md) — execution source of truth
- [Agent rules](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md)
- [Source packet README](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/README.md)
- [Product design (packet)](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/DESIGN.md)
- [Architecture](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md)
- [ADR 0001 — dual-listener lab](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0001-all-in-one-dual-listener-lab.md)
- [ADR 0002 — password KDF and username profile](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0002-password-kdf.md)
- [ADR 0003 — RFC 7924 Cached Information](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0003-cached-information.md)
- [ADR 0004 — TLS 1.3 cipher policy](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0004-tls13-cipher-policy.md)
- [ADR 0005 — ticket lifetime and resumption](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0005-ticket-lifetime.md)
- [ADR 0006 — external PSK / raw public keys](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0006-external-psk-rpk.md)
- [ADR 0007 — internal TACACS codec](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0007-codec-approach.md)
- [ADR 0010 — lab static bearer vs MCP OAuth PRM](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)
- [TACACS conformance](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TACACS_CONFORMANCE.md)
- [REST/MCP API parity](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/API_PARITY.md)
- [Configuration](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md)
- [Testing and benchmarks](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TESTING_AND_BENCHMARKS.md)
- [Lab deployment](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md)
- [Tasks](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TASKS.md)
- [References](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/REFERENCES.md)
- [Generated toolchain record](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/toolchain.md)
- [Generated operation inventory](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/api-parity.md)
- [Generated conformance inventory](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/conformance.md)
- [Contributing](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CONTRIBUTING.md)
- [Security policy](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/SECURITY.md)
- [Code of conduct](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CODE_OF_CONDUCT.md)
- [License](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/LICENSE)

On conflict, the canonical design wins over copied packet documents.

## Prerequisites

- Go **1.24.5** (see `go.mod`)
- Node.js **22.14.0** and npm **10.9.x** (see `.nvmrc` and `web/package.json`)
- `make`

## Local checks

```bash
make test
make test-race
make web-test
make lint
make secrets
make check-registries
make check-generated
make build
./bin/taclabd -h
```

`make bench` runs hot-path benches under `internal/tacacs`, `internal/policy`, `internal/state`, and `internal/aaa` (including header/obfuscation benches). Argon2id KDF benches live under `internal/credentials` and are excluded from that target so KDF cost does not dominate the ordinary suite.

`make ci` is the local equivalent of the GitHub Actions merge gate (without `govulncheck` network install unless you run `make vuln`).
