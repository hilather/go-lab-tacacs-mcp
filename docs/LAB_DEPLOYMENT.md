# Reference Lab Deployment and Replication Requirements

Status: implementation and release contract  
Deployment: single OCI image, single process, single replica  
Primary orchestration: Docker Compose on a Linux host  
Last updated: 2026-08-13

## 1. Purpose

TacLab is intended to make TACACS+ device-administration scenarios reproducible. The reference deployment must allow an agent or operator to start a known baseline, run authentication/authorization/accounting experiments, create temporary state through the UI or APIs, collect evidence, and return to the baseline by restarting or resetting the runtime overlay.

This document defines the lab topology, image requirements, Compose contract, secret layout, certificate setup, device scenarios, test matrix, and release evidence.

## 2. Lab objectives

The reference lab must support all of the following without rebuilding the image:

- Load predefined clients, users, groups, credentials, command permissions, listener settings, and API tokens from a mounted configuration file and secret files.
- Accept legacy TACACS+ on host TCP port 49.
- Accept secure TACACS+ over TLS 1.3 on host TCP port 300.
- Expose the React UI, REST API, MCP endpoint, health checks, and optional metrics endpoint.
- Create, update, shadow, and delete runtime-only users, groups, clients, policies, and API tokens.
- Restore the declared baseline after process restart.
- Exercise ASCII, PAP, CHAP, MS-CHAP v1, MS-CHAP v2, ENABLE, and ASCII password-change behavior.
- Exercise service and command authorization with mandatory and optional AV-pair handling.
- Exercise accounting START, STOP, and WATCHDOG records.
- Exercise single-connect and non-single-connect sessions.
- Exercise malformed, unsupported, timeout, disconnect, and resource-limit behavior.
- Exercise mutual-certificate TLS authentication and all mandatory secure TACACS+ behaviors.
- Demonstrate REST/MCP feature and authorization parity.
- Produce deterministic logs, events, policy traces, and a sanitized effective-configuration export.

## 3. Reference topology

```text
                                      +-----------------------------+
                                      |        Linux lab host       |
                                      |                             |
Browser / REST / MCP client ----------+--> 8080/tcp                 |
                                      |      +------------------+   |
Legacy network devices ---------------+--> 49 -> 4949           |   |
                                      |      |                  |   |
TLS network devices ------------------+--> 300 -> 4300         |   |
                                      |      |  taclab process  |   |
Optional Prometheus ------------------+--> loopback 9090        |   |
                                      |      |                  |   |
                                      |      +------------------+   |
                                      |        read-only config     |
                                      |        Docker secrets       |
                                      +-----------------------------+
```

The initial product intentionally places legacy and TLS listeners in one process to satisfy the all-in-one lab-appliance goal. They remain separate listeners on distinct TCP ports and share no protocol upgrade or fallback path. This is a documented lab convenience, not a recommended production security topology. Production-like evaluations should run a TLS-only instance or separate legacy and TLS instances on different hosts.

## 4. Host requirements

### 4.1 Required

- Linux host capable of running OCI containers.
- Docker Engine and Docker Compose v2, or a compatible runtime that preserves TCP source addresses as documented for the selected network mode.
- Access to host TCP ports 49, 300, and 8080.
- A filesystem location for configuration, public certificates, and secret files.
- Accurate host time for certificate validation, token expiry, events, and accounting timestamps.

### 4.2 Recommended

- Dedicated lab VLAN or isolated bridge network.
- Packet capture capability on the host or mirror interface.
- At least two test client identities: one legacy shared-secret client and one mutual-TLS client.
- A software TACACS test client in addition to physical or virtual network devices.
- Prometheus-compatible metric collection for load tests.
- A CPU-frequency-stable runner for benchmark baselines.

### 4.3 Source-address fidelity

TACACS client selection can depend on the source IP address. Agents must not assume every container network preserves the device address.

Before declaring a topology supported, verify the address observed by TacLab using a connection event and a packet capture. Acceptable reference options include:

1. Normal published ports when the Linux Docker path preserves the source address for the lab topology.
2. Host networking on Linux when source-address fidelity and low setup complexity outweigh namespace isolation.
3. Macvlan or ipvlan when the container must appear directly on the lab network.
4. A dedicated TCP proxy only when its identity is trusted and a separately designed identity-forwarding mechanism is enabled. PROXY protocol support is not implied by the initial architecture.

Client matching must never trust `X-Forwarded-For` or HTTP proxy headers for TACACS connections.

### 4.3.1 How to verify the observed peer

1. Start the reference Compose project (`make lab-gen` then `docker compose -f deployments/compose/compose.yaml up -d --build`).
2. Send a legacy TACACS session from the intended device or from `internal/tacacs/testclient`.
3. Read `/api/v1/events` and the JSON stdout connection/auth records. The selected `client_id` is the compiled match for the TCP peer, not the TACACS `rem_addr` field.
4. On the host, capture the same SYN (`tcpdump -n tcp port 49 or port 300`) and compare the source address to the address you configured in `match.source_cidrs`.

On typical Linux published-port mappings the peer TacLab sees is a docker-proxy or bridge SNAT address, not the device. The generated lab YAML therefore uses `0.0.0.0/0` and `::/0` so the appliance still matches. `configs/lab.example.yaml` keeps the narrow `10.20.0.0/16` / `10.30.0.0/16` lab VLAN example — use that only with host network or macvlan.

`make lab-test` records this disposition as `LAB-SOURCE-001` and **fails** if events omit `client_id` or `remote`. `remote` is the TACACS `rem_addr` field, not the TCP peer used for match. It does **not** claim published-port NAT preserves device addresses.

## 5. Image contract

### 5.1 Build stages

The image must be produced by a reproducible multi-stage build:

1. **Frontend stage** - install locked Node dependencies and build React/TypeScript static assets.
2. **Backend stage** - run generation, Go tests needed for build integrity, and compile the Go server.
3. **Runtime stage** - contain only the server binary, embedded or copied static assets, CA certificates, required license notices, and minimal runtime metadata.

Node.js, npm/pnpm build caches, Go toolchains, compilers, shells, package managers, source trees, and test fixtures must not be present in the final image unless an approved diagnostic image is built under a distinct tag.

### 5.2 Runtime properties

The release image must:

- Run as a fixed non-root UID/GID.
- Listen on unprivileged container ports `4949`, `4300`, and `8080`.
- Rely on host port mapping for TCP 49 and 300.
- Support a read-only root filesystem.
- Use `/tmp` and `/run/taclab` only through bounded tmpfs mounts when needed.
- Write application logs to stdout/stderr.
- Support graceful termination on `SIGTERM` and a documented reload signal.
- Include an OCI health check or Compose health check using the readiness endpoint.
- Include version, commit, build date, Go version, frontend build identifier, config schema version, TACACS conformance baseline, and MCP specification baseline in `/api/v1/status` and `--version` output.
- Carry an SBOM and provenance/attestation in the release pipeline.
- Be scanned for known vulnerabilities before release.
- Avoid `latest` in reproducible lab manifests; use an immutable version or digest.

### 5.3 Container capabilities

No Linux capability should be required when high container ports are mapped from the host. The reference deployment must drop all capabilities and set `no-new-privileges`.

The 1.0 image is `ghcr.io/hilather/go-lab-tacacs-mcp`. Pin a version tag or digest in reproducible labs; do not use `latest`. Every release publishes three runtimes of the same static `taclabd` binary:

| Tag | Runtime |
|---|---|
| `:<tag>` | distroless (Compose default) |
| `:<tag>-ubuntu` | Ubuntu 24.04 |
| `:<tag>-rocky` | Rocky Linux 9 |

A high-port smoke file remains at `deployments/compose/compose.smoke.yaml` (host `14949` → `4949`, `18080` → `8080`) for environments that cannot publish 49/300. `compose.lab-test.yaml` uses the same high host ports for `make lab-test`.

### 5.4 Optional Cisco IOL lab (Containerlab)

`make cisco-lab` deploys [deployments/containerlab](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/deployments/containerlab/README.md): a `cisco_iol` node (operator-built vrnetlab image from CML refplat) plus TacLab on the Containerlab management network, legacy TACACS+ to port 4949.

This path is **not** part of `make lab-test` / `ci-gate`. If Containerlab or `TACLAB_IOL_IMAGE` is missing, the same entry point prints an equipment-gap **SKIP** and exits 0. Do not treat that skip as Cisco PASS or device-family completeness. Do not commit IOL binaries or refplat ISOs.

## 6. Reference directory layout

```text
taclab-lab/
├── compose.yaml
├── config/
│   └── taclab.yaml
├── certs-public/
│   ├── client-ca.pem
│   ├── client-crl.pem
│   └── server-chain.pem
├── secrets/
│   ├── api_admin_token
│   ├── tacacs_server_key.pem
│   ├── lab_switches_tacacs_secret
│   ├── lab_admin_argon2id
│   ├── lab_admin_challenge_secret
│   ├── lab_admin_enable_argon2id
│   ├── lab_readonly_argon2id
│   └── lab_disabled_argon2id
├── evidence/
│   ├── captures/
│   ├── events/
│   ├── exports/
│   └── reports/
└── README.md
```

The `secrets` directory must be excluded from source control. The lab README should contain generation commands and purpose descriptions, not secret values.

## 7. Reference Compose shape

Agents must maintain a working Compose example equivalent to the following. Exact image coordinates and health-check tooling may vary.

```yaml
services:
  taclab:
    image: ghcr.io/hilather/go-lab-tacacs-mcp:0.1.0
    container_name: taclab
    restart: unless-stopped

    ports:
      - target: 4949
        published: 49
        protocol: tcp
      - target: 4300
        published: 300
        protocol: tcp
      - target: 8080
        published: 8080
        protocol: tcp

    command:
      - serve
      - --config=/etc/taclab/taclab.yaml

    volumes:
      - type: bind
        source: ./config/taclab.yaml
        target: /etc/taclab/taclab.yaml
        read_only: true
      - type: bind
        source: ./certs-public
        target: /etc/taclab/certs-public
        read_only: true

    secrets:
      - api_admin_token
      - tacacs_server_key
      - lab_switches_tacacs_secret
      - lab_admin_argon2id
      - lab_admin_challenge_secret
      - lab_admin_enable_argon2id
      - lab_readonly_argon2id
      - lab_disabled_argon2id

    read_only: true
    tmpfs:
      - /tmp:size=32m,mode=1777
      - /run/taclab:size=16m,mode=0700,uid=10001,gid=10001

    user: "10001:10001"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true

    stop_grace_period: 20s

    healthcheck:
      test: ["CMD", "/usr/local/bin/taclabd", "healthcheck", "--url=http://127.0.0.1:8080/health/ready"]
      interval: 10s
      timeout: 3s
      retries: 6
      start_period: 5s

secrets:
  api_admin_token:
    file: ./secrets/api_admin_token
  tacacs_server_key:
    file: ./secrets/tacacs_server_key.pem
  lab_switches_tacacs_secret:
    file: ./secrets/lab_switches_tacacs_secret
  lab_admin_argon2id:
    file: ./secrets/lab_admin_argon2id
  lab_admin_challenge_secret:
    file: ./secrets/lab_admin_challenge_secret
  lab_admin_enable_argon2id:
    file: ./secrets/lab_admin_enable_argon2id
  lab_readonly_argon2id:
    file: ./secrets/lab_readonly_argon2id
  lab_disabled_argon2id:
    file: ./secrets/lab_disabled_argon2id
```

The checked-in example must use placeholders or generation instructions. It must never contain live credentials or private keys.

## 8. Configuration-to-secret path mapping

Inside the container, Compose secrets are normally available under `/run/secrets/<name>`. The baseline configuration should refer to those exact paths.

Public certificate chains and CRLs may be mounted read-only under `/etc/taclab/certs-public`. Private keys remain secret mounts.

The config validator must fail readiness when a required secret cannot be loaded. It must not include secret file contents in the error.

### 8.1 Legacy shared-secret lifecycle

The reference generator creates a unique legacy TACACS shared secret of at least 32 characters and writes it only to the Docker secret file. The baseline YAML stores only its reference plus non-secret `last_rotated_at` and `rotation_interval` metadata.

The reference lab must demonstrate:

- enforceable minimum length and character-class policy.
- successful loading of a key longer than 32 characters without truncation.
- startup/reload warnings when process-local keyed HMAC comparison detects reuse, without returning or persisting the comparison value.
- deterministic `current`, `due_soon`, `overdue`, and `unknown` lifecycle status using controlled test time.
- safe rotation by replacing the secret file and lifecycle metadata, validating the candidate, and publishing one atomic reload.
- no old/new secret value in logs, events, metrics, REST, MCP, UI, evidence, or exported configuration.

Reuse and overdue status are warnings in the reference profile so historical lab topologies can be reproduced. A strict profile may reject them, but REST, MCP, UI, configuration validation, and documentation must expose identical behavior.

## 9. Certificate lab

Generate the reference tree with `go run ./tools/labcerts <dir>` (`internal/tacacs/tls.GenerateLabPKI`). Tests materialize the same set under a temp directory so private keys are never committed.

### 9.1 Minimum identities

The reference secure TACACS lab needs:

- One lab root or intermediate CA used to issue the server certificate.
- One server certificate with a DNS or IP identity matching the name used by the client.
- One private key for the server certificate.
- One client CA trust bundle.
- At least two client certificates:
  - An authorized device certificate whose identity maps to `secure-routers`.
  - A valid but unauthorized certificate to test policy rejection.
- One expired or revoked certificate for negative tests.
- A CRL or test revocation mechanism supported by the implementation.

### 9.2 Certificate constraints

The reference setup must verify:

- TLS 1.3 only.
- Both peers authenticate in the normal certificate profile.
- Certificate path validation succeeds only for the configured trust chain.
- Server identity validation is exercised by the test client.
- Client identity maps deterministically to exactly one configured client.
- Invalid, expired, not-yet-valid, revoked, wrong-EKU, wrong-name, unknown-CA, and unauthorized valid certificates are rejected.
- No TACACS packet is accepted before the TLS handshake completes.
- Early data is rejected.
- Legacy packet obfuscation is not used inside TLS.
- TLS listener traffic cannot downgrade or fall back to the legacy listener.

### 9.3 Optional TLS modes

External PSK and raw-public-key authentication are optional protocol features. They remain explicitly tracked in `TACACS_CONFORMANCE.md`. Adding either mode requires:

- Separate configuration and secret types.
- No reuse of legacy TACACS shared secrets.
- Dedicated positive and negative interoperability tests.
- REST/MCP/UI parity for supported configuration and diagnostics.
- Security documentation and benchmark coverage.

## 10. API and UI access model

### 10.1 Lab bearer token

The default lab mode uses a bootstrap bearer token loaded from a secret file. The same token verifier and scopes protect REST and MCP operations.

The browser login flow should exchange a valid bearer token for a short-lived HttpOnly session cookie. The raw token must not be stored persistently in browser local storage or included in frontend logs.

### 10.2 Network exposure

- Bind the HTTP listener to the lab management network only when possible.
- Use an HTTPS reverse proxy or native HTTPS when requests cross an untrusted network.
- Do not expose profiling endpoints on the management interface by default.
- Bind metrics to loopback or a dedicated monitoring network.
- Ensure CORS is disabled or restricted to explicit trusted origins.

### 10.3 MCP endpoint

Operator and agent setup for **local** Streamable HTTP clients and **remote/hosted** HTTPS is in [MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md). First boot is [QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md). Users, groups, clients, and secret files: [BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md).

The MCP endpoint is `POST /mcp` on the same HTTP listener as REST. Clients send `Authorization: Bearer`, `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, per-request `_meta`, and `Mcp-Name` for `tools/call` / `resources/read`. GET/DELETE `/mcp` return 405. There is no `.well-known/oauth-protected-resource` ([ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)). Origin: missing Origin is allowed with a valid bearer unless `api.mcp.require_origin` is true. `subscriptions/listen` notifies URIs only; pull bodies with `taclab.events.list`. The transport uses the official Go SDK ([ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)). Clients should send `Accept: application/json, text/event-stream` (the adapter fills a missing Accept header).

## 11. Baseline lab personas

The checked-in example should define at least these logical personas:

| Persona | Purpose | Expected behavior |
|---|---|---|
| `lab-admin` | Full command administration | ASCII/PAP and challenge methods when configured; privilege 15; all commands permitted |
| `lab-readonly` | Operational inspection | Login permitted; privilege 1; `show`, `ping`, and traceroute permitted; configuration commands denied |
| `lab-disabled` | Negative authentication | Authentication denied with no policy leakage |
| Runtime temporary user | API/UI mutation test | Created without baseline edit; disappears after restart |
| Runtime shadow user | Overlay test | Temporarily replaces a baseline identity; reset restores baseline behavior |

Use non-production sample identities and generated lab-only secrets.

## 12. Required device and client profiles

A release candidate must be tested against:

1. The project's protocol-level Go integration client.
2. At least one independent TACACS+ client or server implementation used as an interoperability peer.
3. At least one network operating system or virtual network appliance supporting legacy TACACS+.
4. A secure TACACS+ TLS test peer as implementations become available in the lab.

Vendor-specific fixtures must be data-driven. Do not add vendor conditionals to the core protocol engine unless the behavior is required to interpret a documented standards ambiguity and is protected by an explicit compatibility profile.

## 13. Lab scenario catalog

Each scenario has a stable ID, setup fixture, expected protocol exchange, expected event output, and cleanup action.

### LAB-LEGACY-001: Shared-secret policy and lifecycle

- Validate a unique generated secret, a key longer than 32 characters, a too-short/weak key, a reused key, and due/overdue rotation metadata.
- Rotate the valid secret by replacing its file and lifecycle metadata, reload atomically, and prove old-secret failure/new-secret success.
- Assert REST/MCP/UI warning parity and complete secret-canary redaction.

### LAB-AUTH-001: ASCII success

- Configure an enabled user with a valid login verifier.
- Authenticate from an allowed legacy client.
- Expect successful multi-step ASCII completion, redacted event data, and no secret in logs.

### LAB-AUTH-002: ASCII failure

- Submit an incorrect password.
- Expect a generic failure, bounded retry behavior, and no user-enumeration detail.

### LAB-AUTH-003: PAP success/failure

- Exercise both valid and invalid credentials.
- Verify expected version/type behavior and response statuses.

### LAB-AUTH-004: CHAP

- Use a user with challenge secret material.
- Verify a correct response succeeds and incorrect challenge/response data fails.

### LAB-AUTH-005: MS-CHAP v1

- Verify correct challenge response, malformed length rejection, and unavailable-credential behavior.

### LAB-AUTH-006: MS-CHAP v2

- Verify correct response, malformed data, peer challenge differences, and unavailable-credential behavior.

### LAB-AUTH-007: ENABLE

- Exercise correct and incorrect ENABLE credentials and client restrictions.

### LAB-AUTH-008: ASCII password change

- Exercise the complete conversation, verifier update in runtime overlay, rollback on failure, and baseline restoration after restart.

### LAB-AUTHZ-001: Shell service

- Request shell authorization.
- Verify privilege attribute behavior and PASS_ADD/PASS_REPL semantics as configured.

### LAB-AUTHZ-002: Read-only command permit

- `show running-config` or an equivalent fixture is permitted for `lab-readonly`.
- Policy trace identifies the exact group and rule.

### LAB-AUTHZ-003: Configuration command deny

- A configuration-changing command is denied.
- No lower-priority permit overrides a prior deterministic deny.

### LAB-AUTHZ-004: Attribute handling

- Exercise mandatory (`=`) and optional (`*`) AV pairs, duplicates, ordering, replacements, additions, and malformed attributes.

### LAB-ACCT-001: START/STOP

- Send valid START and STOP records with session correlation attributes.
- Verify acknowledgement and event representation.

### LAB-ACCT-002: WATCHDOG

- Send valid WATCHDOG update records.
- Verify flags and event type.

### LAB-ACCT-003: Invalid flag combinations

- Send no accounting action flag or multiple mutually exclusive flags.
- Verify protocol-safe rejection/error handling.

### LAB-CONN-001: Non-single-connect

- Complete one session and verify connection closure behavior.

### LAB-CONN-002: Single-connect multiplexing

- Negotiate single-connect.
- Run concurrent session IDs over one connection.
- Verify isolated sequencing and correct cleanup.

### LAB-CONN-003: Resource limits

- Exceed session, connection, packet, and timeout limits individually.
- Verify bounded resources and unaffected unrelated connections.

### LAB-TLS-001: Mutual certificate success

- Present trusted server and client certificates.
- Complete TACACS exchange over TLS 1.3 on port 300.

### LAB-TLS-002: Certificate negatives

- Run each certificate failure class defined in Section 9.2.
- Verify rejection before TACACS processing.

### LAB-TLS-003: No early data or downgrade

- Attempt early data and plaintext traffic on the TLS listener.
- Verify abrupt rejection and no fallback.

### LAB-API-001: REST/MCP read parity

- Invoke each read operation with equivalent inputs.
- Compare normalized result, authorization, error code, and revision.

### LAB-API-002: REST/MCP mutation parity

- Create equivalent runtime users/groups/clients/tokens through both surfaces.
- Compare resulting effective state and events.

### LAB-STATE-001: Restart reset

- Create runtime objects and tombstones.
- Restart the container.
- Verify only the mounted baseline remains.

### LAB-STATE-002: Reload rebase

- Modify the mounted baseline deliberately.
- Validate and reload.
- Verify runtime overlay rebase or atomic rollback on conflict.

## 14. Automated Compose test workflow

The repository target is:

```text
make lab-test
```

`tools/labgen` writes the ephemeral directory (`go run ./tools/labgen <dir>`). `tools/lab-test.sh` builds `ghcr.io/hilather/go-lab-tacacs-mcp:<version>`, generates secrets/certs, starts a unique Compose project with `compose.lab-test.yaml` (high host ports), runs LAB-*, restarts, and writes `dist/lab-test-report.json`.

The target should:

1. Build or pull a pinned image.
2. Generate ephemeral lab certificates and secrets in a temporary directory.
3. Render the example configuration with absolute test paths as needed.
4. Start the Compose project under a unique project name.
5. Wait for readiness with a bounded timeout.
6. Run REST, MCP, legacy TACACS, TLS TACACS, UI smoke, and restart/reset scenarios.
7. Capture logs, events, metrics, and packet traces needed for failure diagnosis.
8. Assert no secret canary appears in evidence.
9. Stop and remove containers, networks, and temporary secrets even on failure.
10. Publish a machine-readable test report in CI.

Tests must not depend on a developer's existing containers, ports, Docker network names, or home-directory files.

## 15. Health semantics

### 15.1 Liveness

`/health/live` answers whether the process event loop is responsive. It must not fail merely because a remote client, external log collector, or optional metric consumer is unavailable.

### 15.2 Readiness

`/health/ready` succeeds only when:

- Baseline configuration is valid.
- Required secrets are loaded.
- The initial compiled snapshot is published.
- Every enabled required listener is bound.
- The operation registry and REST/MCP schemas passed startup consistency checks.

A later failure of one listener must update readiness and emit an event.

Health responses expose no credentials or full configuration.

## 16. Logging and evidence

### 16.1 Required structured fields

Events and logs should include, where applicable:

- Timestamp.
- Instance ID.
- Effective revision.
- Transport (`legacy` or `tls`).
- Listener ID.
- Connection ID.
- TACACS session ID.
- Client ID after successful matching.
- Username in the configured privacy mode.
- Operation or packet type.
- Result/status.
- Stable error code.
- Policy rule ID for authorization decisions.
- Duration and bounded size/count fields.

Never include passwords, challenge secrets, shared secrets, bearer tokens, private keys, complete CHAP/MS-CHAP material, or raw sensitive packet bodies.

### 16.2 Evidence bundle

A release or interoperability run should retain:

```text
manifest.json
versions.txt
sanitized-effective-config.yaml
conformance-results.json
api-parity-results.json
junit.xml
benchmark-summary.json
metrics-snapshot.txt
redacted-events.jsonl
redacted-server.log
packet-capture-notes.md
```

Packet captures may contain sensitive lab protocol data and must be handled as restricted artifacts even when lab-only credentials are used.

## 17. Performance lab profiles

### 17.1 Small reference profile

- 10 clients.
- 100 users.
- 10 groups.
- 100 command rules.
- 100 concurrent connections.
- 500 authentication/authorization requests per second combined.

### 17.2 Standard reference profile

- 500 clients.
- 5,000 users.
- 100 groups.
- 5,000 command rules.
- 1,000 concurrent connections.
- 5,000 requests per second combined.

### 17.3 Maximum configured profile

- Object counts at configured limits.
- Connection/session counts at test-host-safe limits.
- Mixed successful and failed authentication.
- Mixed authorization and accounting.
- Concurrent event streaming and API reads.
- Periodic runtime mutation and config compilation outside the packet hot path.

Performance claims must state CPU, memory, operating system, Go version, image digest, profile, transport, authentication method, and whether race instrumentation was disabled.

## 18. Security-negative lab requirements

Automate at least:

- Plaintext TACACS sent to TLS port.
- TLS ClientHello sent to legacy port.
- TLS below version 1.3.
- Missing/invalid client certificate.
- TLS early data.
- Invalid legacy shared secret.
- Too-short or weak legacy shared secret.
- Reused legacy shared secret warning and strict-profile rejection.
- Due-soon/overdue/unknown rotation status and notification deduplication.
- Packet body too large.
- Truncated headers and bodies.
- Invalid TACACS major/minor version combinations.
- Invalid sequence transitions.
- Session ID collision on a single connection.
- Excessive authentication continuation rounds.
- Regex and policy input boundary cases.
- API request without token.
- Token with insufficient scope.
- Expired/revoked token.
- Stale revision mutation.
- Cross-site request and cookie protections for UI sessions.
- Secret canaries in all logs, traces, metrics, events, REST, MCP, UI, and export outputs.

## 19. Upgrade and rollback

The lab deployment must support deterministic rollback:

1. Keep the existing baseline config and secret set.
2. Pin the image by version or digest.
3. Validate the candidate image against the mounted configuration using a non-serving command.
4. Run migration validation if schema versions differ.
5. Start the candidate and run smoke/conformance tests.
6. Roll back to the prior image if readiness or acceptance checks fail.

Because runtime state is memory-only, an image replacement intentionally discards temporary changes. Export sanitized effective state before replacement when experiment evidence is needed.

## 20. Deployment definition of done

A deployment-related change is complete only when:

- [x] The release image builds reproducibly from a clean checkout.
- [x] Frontend and backend versions are aligned and reported.
- [x] The final image contains no build toolchain or source secrets.
- [x] The container runs as non-root with all capabilities dropped.
- [x] Read-only root filesystem operation passes.
- [x] Port mappings 49, 300, and 8080 work on the reference Linux host.
- [x] Source-IP behavior has an automated or documented verification.
- [x] Baseline config and all secret references load through Compose.
- [ ] Shared-secret complexity, uniqueness warning, lifecycle status, and rotation workflow pass across config, REST, MCP, UI, events, and evidence.
- [x] Legacy and TLS listeners pass their smoke and negative tests.
- [x] The restart-reset scenario passes.
- [x] REST/MCP parity and UI smoke tests pass against the image.
- [x] Health checks reflect listener and snapshot readiness accurately.
- [x] Logs and evidence contain no secret canaries.
- [ ] Resource usage and benchmark evidence are recorded.
- [x] Compose, certificate-generation, operator, and troubleshooting documentation are updated in the same change.
