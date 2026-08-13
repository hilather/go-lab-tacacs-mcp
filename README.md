# TacLab (`taclabd`)

TacLab is an all-in-one Go TACACS+ / MCP lab appliance. The repository name is `go-lab-tacacs-mcp`; the product name is **TacLab** and the binary is **`taclabd`**.

| Item | Value |
|---|---|
| Go module | `github.com/hilather/go-lab-tacacs-mcp` |
| Image | `ghcr.io/hilather/go-lab-tacacs-mcp` |
| License | Apache-2.0 |
| Go | 1.25.0 |
| Node.js | 22.14.0 |
| MCP specification | 2026-07-28 |
| Official MCP Go SDK baseline | `github.com/modelcontextprotocol/go-sdk v1.7.0` (recorded; not imported — requires Go 1.25; see [ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)) |

This checkout is the **1.0 lab appliance**. RFC 8907 and RFC 9887 **server `MUST` / `MUST NOT` / `PROJECT MUST`** rows are `PASS` or `N/A_RFC_DEPRECATED` with evidence IDs in [testdata/conformance](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/testdata/conformance/rfc8907.yaml). `make check-registries` includes the `-release` gate.

The required software peer is the in-tree `internal/tacacs/testclient` (separate codec). **Cisco and second-NOS interop are skipped** (no hardware) — see [interop notes](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/INTEROP.md). Lab static bearer is ADR 0010. Device-family completeness is **not** claimed.

ASCII LOGIN, PAP, CHAP, MS-CHAP v1/v2, ENABLE, and ASCII CHPASS are implemented, plus service and command authorization, the RFC 8907 accounting flag table, a bounded event ring, dual TACACS listeners (legacy and TLS 1.3), REST/MCP parity, and the embedded SPA. REST/MCP equivalence is enforced by the `internal/api/parity` harness. Metrics and governors live under `internal/observability` (pprof off by default).


Reference Compose lab (host 49 / 300 / 8080, non-root, read-only rootfs):

```bash
go run ./tools/labgen deployments/compose
docker compose -f deployments/compose/compose.yaml up -d --build
```

TLS-only profile (no legacy port 49):

```bash
docker compose -f deployments/compose/compose.yaml -f deployments/compose/compose.tls-only.yaml up -d --build
```

Container acceptance (`LAB-*`, restart reset, SSE survives `write_timeout`):

```bash
make lab-test
```

High-port smoke without generated PKI (no privileged 49/300):

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
- [ADR 0011 — thin MCP adapter on Go 1.24.5](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)
- [ADR 0012 — ASCII/PAP enablement warning](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md)
- [Operator guide (1.0)](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md)
- [Developer workflow](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/DEVELOPER.md)
- [Interop notes](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/INTEROP.md)
- [Maintenance policy](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MAINTENANCE.md)
- [Changelog](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CHANGELOG.md)
- [Benchmark budgets](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/benchmarks/budgets.yaml)
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
- [Threat model](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/THREAT_MODEL.md)
- [Security policy](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/SECURITY.md)
- [Code of conduct](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CODE_OF_CONDUCT.md)
- [License](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/LICENSE)

On conflict, the canonical design wins over copied packet documents.

## Prerequisites

- Go **1.25.0** (see `go.mod`)
- Node.js **22.14.0** and npm **10.9.x** (see `.nvmrc` and `web/package.json`)
- `make`

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
make build
./bin/taclabd -h
make lab-test
```

`make bench` runs hot-path benches under `internal/tacacs`, `internal/policy`, `internal/state`, and `internal/aaa` (including header/obfuscation benches). Argon2id KDF benches live under `internal/credentials` and are excluded from that target so KDF cost does not dominate the ordinary suite.

`make ci` is the local equivalent of the GitHub Actions merge gate (without `govulncheck` network install unless you run `make vuln`).
