# TacLab Server Implementation Packet

Status: implementation baseline  
Architecture: all-in-one Go backend with a React and TypeScript web application  
Deployment target: reproducible lab environments using an OCI/Docker image  
Specification baseline: RFC 8907, RFC 9887, and MCP 2026-07-28  
Last updated: 2026-08-13

## Purpose

This packet is the historical implementation contract for agents and contributors building **TacLab**. The execution source of truth for this repository is [CANONICAL_DESIGN.md](CANONICAL_DESIGN.md); that document wins on conflict.

TacLab is one Go process with four externally visible surfaces:

1. Legacy TACACS+ over TCP.
2. Secure TACACS+ over TLS 1.3.
3. A versioned REST API and embedded React web UI.
4. An MCP server with feature parity with the REST API.

The source configuration defines the repeatable lab baseline: clients, users, groups, permissions, listeners, TLS settings, and initial API tokens. Administrators may create additional users, groups, clients, policies, and API tokens at runtime. Runtime changes are held in memory, override the baseline predictably, and disappear on process restart unless a future persistence adapter is explicitly enabled.

## Required reading order

Agents must read these files before modifying implementation code:

1. [AGENTS.md](../AGENTS.md) - non-negotiable contribution and implementation rules.
2. [CANONICAL_DESIGN.md](CANONICAL_DESIGN.md) - execution source of truth.
3. [DESIGN.md](DESIGN.md) - packet product and system design (historical).
4. [ARCHITECTURE.md](ARCHITECTURE.md) - package boundaries, data flow, and dependency rules.
5. [decisions/0001-all-in-one-dual-listener-lab.md](decisions/0001-all-in-one-dual-listener-lab.md) - accepted lab topology and transport-isolation safeguards.
6. [decisions/0007-codec-approach.md](decisions/0007-codec-approach.md) - accepted internal TACACS+ codec default.
7. [decisions/0002-password-kdf.md](decisions/0002-password-kdf.md) - Argon2id parameters, UsernameCasePreserved, MS-CHAP v2 username.
8. [TACACS_CONFORMANCE.md](TACACS_CONFORMANCE.md) - release-blocking protocol matrix.
9. [API_PARITY.md](API_PARITY.md) - REST/MCP parity contract.
10. [CONFIGURATION.md](CONFIGURATION.md) - configuration and runtime-overlay model.
11. [TESTING_AND_BENCHMARKS.md](TESTING_AND_BENCHMARKS.md) - mandatory regression, conformance, fuzz, race, and benchmark policy.
12. [LAB_DEPLOYMENT.md](LAB_DEPLOYMENT.md) - container and reference lab requirements.
13. [TASKS.md](TASKS.md) - phased implementation backlog and acceptance gates.
14. [REFERENCES.md](REFERENCES.md) - normative and implementation references.
15. [THREAT_MODEL.md](THREAT_MODEL.md) - trust boundaries, abuse cases, and test links.
16. [OPERATOR.md](OPERATOR.md) - 1.0 operator guide.
17. [QUICKSTART.md](QUICKSTART.md) - clone, generate, Compose, first REST/MCP call.
18. [MCP.md](MCP.md) - MCP Streamable HTTP: local client setup and remote/hosted setup.
19. [BASELINE.md](BASELINE.md) - configure users, groups, clients, tokens, and secret files.
20. [DEVELOPER.md](DEVELOPER.md) - conformance, parity, and generate workflow.
21. [INTEROP.md](INTEROP.md) - software peer and device-skip record.
22. [MAINTENANCE.md](MAINTENANCE.md) - supported versions and rerun triggers.
23. [decisions/0012-ascii-pap-enablement-warning.md](decisions/0012-ascii-pap-enablement-warning.md) - T89-SEC-002 disposition.

## Product-level release gates

A release may not be described as complete unless all of the following are true:

- The RFC 8907 and RFC 9887 conformance matrix has no unresolved `MUST` or `MUST NOT` item.
- Every `SHOULD` item that is not implemented has an approved architecture decision record explaining the disposition and interoperability impact.
- All supported authentication, authorization, accounting, connection, and TLS behaviors have automated regression coverage.
- REST and MCP parity tests pass, and the generated parity documentation is current.
- The React UI consumes only the public REST API and does not bypass authorization or mutate state through private endpoints.
- Unit, integration, end-to-end, race, fuzz-seed, frontend, and container tests pass.
- Performance benchmark results are attached to the release and meet the regression policy.
- No generated documentation or schema file differs from the checked-in version.
- The image runs as a non-root user with a read-only root filesystem in the reference Compose deployment.
- A restart restores the declared configuration baseline and removes all runtime-only state.

## Planned repository shape

```text
.
├── AGENTS.md
├── README.md
├── cmd/
│   └── taclabd/
├── internal/
│   ├── aaa/
│   ├── api/
│   │   ├── auth/
│   │   ├── mcp/
│   │   ├── operations/
│   │   └── rest/
│   ├── config/
│   ├── credentials/
│   ├── events/
│   ├── observability/
│   ├── policy/
│   ├── state/
│   └── tacacs/
│       ├── codec/
│       ├── legacy/
│       ├── server/
│       └── tls/
├── web/
│   ├── src/
│   └── package.json
├── api/
│   ├── openapi.yaml
│   └── operations.yaml
├── configs/
│   └── lab.example.yaml
├── testdata/
│   ├── protocol/
│   ├── policies/
│   └── vendors/
├── deployments/
│   └── compose/
└── docs/
```

The exact directory names may evolve through an approved architecture decision, but the dependency and ownership rules in `docs/ARCHITECTURE.md` remain binding.
