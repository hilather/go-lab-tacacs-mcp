# Agent Implementation Instructions

Status: mandatory  
Applies to: every code, configuration, test, schema, UI, deployment, and documentation change  
Last updated: 2026-08-14

## 1. Mission

Build TacLab as a protocol-correct, deterministic, observable, and reproducible TACACS+ **and RADIUS** lab server. Favor explicit behavior and testable contracts over convenience or hidden magic.

The implementation must remain a single deployable Go service with an embedded React/TypeScript UI. Runtime-created objects are ephemeral by default. The configured baseline is immutable at runtime and is restored after restart.

Do **not** claim complete RADIUS support. RADIUS is adopted architecturally ([ADR 0013](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0013-add-radius-to-existing-taclab-process.md)–[0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md)); listeners, codec, and policy land in later PRs. Product/module/binary/image names stay `TacLab` / `go-lab-tacacs-mcp` / `taclabd` / `ghcr.io/hilather/go-lab-tacacs-mcp`.

## 1.1 First-time environment setup

Do this before the first code change. Operator onboarding is [docs/QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md). Initial users/groups/clients/secrets: [docs/BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md). MCP local **and** remote (hosted) setup is [docs/MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md).

### Toolchains

| Tool | Pin |
|---|---|
| Go | **1.25.13** (`go.mod` `toolchain`, module `go 1.25.0`) |
| Node.js | **22.14.0** (`.nvmrc`) |
| npm | **10.9.x** (`web/package.json` `packageManager`) |
| Docker Compose | v2, for the reference lab |

### Clone and prove the tree

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
make test
make check-registries
make docs-check
```

`make ci` is the full merge-gate equivalent. Do not skip `check-registries` (`-release`) or claim complete TACACS+ if it fails.

### Bring the lab up (local)

```bash
make lab-gen
docker compose -f deployments/compose/compose.yaml up -d --build
curl -sf http://127.0.0.1:8080/health/ready
```

Bootstrap bearer: `deployments/compose/secrets/api_admin_token`. UI: `http://127.0.0.1:8080`. Edit users/groups/clients in `deployments/compose/config/taclab.yaml` — [docs/BASELINE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/BASELINE.md).

### Connect MCP — local

Point a **2026-07-28 Streamable HTTP** client at `http://127.0.0.1:8080/mcp` with:

- `Authorization: Bearer <token>`
- `MCP-Protocol-Version: 2026-07-28`

There is **no** `.well-known/oauth-protected-resource` ([ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)). Clients that require OAuth PRM cannot discover this server. `POST` only.

Copy-paste client JSON and a `tools/list` curl: [docs/MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md) §3.

### Connect MCP — remote / hosted

1. Deploy the same Compose (or a pinned `ghcr.io/hilather/go-lab-tacacs-mcp:<tag>`) on the lab host.
2. Terminate HTTPS in front of `:8080`. Do not strip `Authorization`, `MCP-Protocol-Version`, `Mcp-Method`, or `Mcp-Name`.
3. Disable proxy buffering and raise read timeout for `subscriptions/listen`.
4. Point the client at `https://<host>/mcp` with the same headers.
5. Keep ports 49 and 300 (TACACS) and 1812/1813 (RADIUS/UDP), 3799 (DAS, default off), and 2083 (RadSec, default off) off the public internet when enabled. Inbound :3799 is an RFC 5176 echo fixture that only updates TacLab’s memory index. It does not kick a NAS.

Caddy/nginx snippets and the remote checklist: [docs/MCP.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MCP.md) §4.

### How you must drive MCP

```text
- Use taclab.* tools from tools/list. Missing tool ⇒ missing scope, not a
  missing feature. Do not invent REST wrappers around MCP or the reverse.
- Mutating calls send expected_revision from the last read.
- Token values appear only on taclab.tokens.create. Never log secrets.
- subscriptions/listen notifies URI only; pull bodies with taclab.events.list.
- Overlay is memory-only. runtime.reset / restart restores the YAML baseline.
```

### Required reading before implementation

1. This file (all of it).
2. [docs/CANONICAL_DESIGN.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md) — wins on conflict.
3. [docs/ARCHITECTURE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md)
4. [docs/API_PARITY.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/API_PARITY.md) for any REST/MCP change.
5. [docs/TACACS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TACACS_CONFORMANCE.md) for any TACACS protocol change.
6. [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) and [docs/designs/radius-authentication.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-authentication.md) for any RADIUS change. Use pack task IDs `RAD-*`.

After every push, watch GitHub Actions until green (§9).

## 2. Non-negotiable engineering rules

### 2.1 Read the contracts first

Before changing implementation code, read the relevant design, architecture, conformance, API parity, configuration, testing, and task sections. Do not infer protocol behavior from a third-party library or from memory when the RFC or MCP specification defines it.

### 2.2 Never bypass the application service layer

TACACS listeners, RADIUS listeners (when enabled), REST handlers, MCP tools/resources, and the React UI must converge on the same typed application operations and state snapshot. Do not duplicate authorization, validation, policy evaluation, redaction, revision handling, or business logic in adapters.

Required dependency direction:

```text
transport or UI adapter -> application operation -> domain service -> state/policy/event interface
```

Forbidden dependency direction:

```text
policy -> REST
state -> MCP
TACACS -> React
MCP -> REST over HTTP
REST -> MCP
UI -> private Go handler
```

### 2.3 Keep REST and MCP feature parity

Every new user-visible administrative capability must declare one of these dispositions:

- `PARITY_REQUIRED`: equivalent REST and MCP operations are required in the same change.
- `REST_ONLY_PROTOCOL`: REST-specific infrastructure such as OpenAPI delivery, browser session bootstrap, health, or SSE framing.
- `MCP_ONLY_PROTOCOL`: MCP discovery, capability negotiation, or protocol-specific subscription mechanics.
- `EXEMPT_BY_ADR`: a reviewed exception with a documented reason and follow-up decision.

For `PARITY_REQUIRED` operations, the change must use the same:

- Go request and response domain types.
- Validation and normalization.
- authorization scopes.
- optimistic-concurrency and revision rules.
- side effects and event records.
- secret-redaction policy.
- error taxonomy.
- idempotency behavior.

The parity registry, tests, and generated matrix must be updated in the same commit. A REST endpoint may not ship first with a promise to add MCP later, or vice versa.

### 2.4 Add regression tests for every defect and behavior change

Every defect fix must begin with a test that fails for the reported behavior. The final change must make that test pass without weakening an existing assertion.

Every new feature must include, as applicable:

- domain unit tests.
- protocol codec or state-machine tests.
- REST contract tests.
- MCP contract tests.
- REST/MCP equivalence tests.
- UI component or end-to-end tests.
- container/lab integration tests.
- security-negative tests.

Do not mark a task complete using manual testing alone.

### 2.5 Add and maintain performance benchmarks

Changes to protocol parsing, authentication dispatch, policy evaluation, state compilation, event ingestion, API serialization, or hot UI data paths must include or update benchmarks.

For a performance-sensitive change:

1. Add a benchmark that represents the affected workload.
2. Capture a baseline using the documented reference command and fixture.
3. Capture the new result under the same conditions.
4. Compare using `benchstat` or the repository-approved equivalent.
5. Record material changes in the pull request and benchmark history.

Do not trade credential security for benchmark numbers. Password KDF cost is intentionally excluded from ordinary policy-engine latency budgets and receives a separate security benchmark.

A regression greater than 10 percent in median or p95 latency, greater than 15 percent in allocations or memory per operation, or a new unbounded growth pattern requires an approved explanation or redesign.

### 2.6 Keep documentation current in the same change

Documentation is part of the implementation, not cleanup work. A change is incomplete until all affected documentation is updated.

At minimum, evaluate and update:

- architecture and design.
- TACACS conformance status.
- RADIUS conformance status (do not mark PASS without evidence; do not advertise completeness).
- REST/MCP parity matrix.
- OpenAPI and MCP schemas.
- configuration reference and examples.
- task status and acceptance evidence.
- deployment instructions.
- benchmark baselines.
- operator-facing behavior and migration notes.

Generated documentation must be regenerated, checked in, and verified clean by CI. Never hand-edit generated files without changing their source.

### 2.7 Protocol completeness is a release requirement

“Complete TACACS+ support” means:

- All current RFC 8907 core authentication flows are implemented or, where the RFC deprecates an option, explicitly rejected with the required behavior and regression tests.
- Authorization and accounting packet forms, statuses, AV-pair semantics, standard dictionaries, optional/mandatory separators, and arbitrary vendor AV pairs are handled.
- Connection multiplexing, limits, malformed packets, sequence rules, session termination, client matching, and legacy obfuscation behavior are tested.
- RFC 8907 shared-secret management requirements are implemented: per-client secrets, at least 32-character support, configurable minimum complexity, lifecycle tracking/notification, reuse warning, and complete redaction.
- All RFC 9887 `MUST` and `MUST NOT` requirements are implemented for secure TACACS+ over TLS 1.3.
- Every normative requirement has a conformance test or a documented test rationale.

Do not claim support based only on a library README. Verify behavior with independent packet fixtures and interoperability tests.

“Complete RADIUS support” means, when it is later advertised:

- RFC 2865 Access-Request/Accept/Reject with bounded packet/attribute framing, VSA preservation, Proxy-State order, PAP and CHAP, and Response Authenticator evidence.
- RFC 2866 Accounting-Request/Response for Start, Stop, Interim-Update, Accounting-On, and Accounting-Off, with authenticator validation before side effects.
- RFC 2869 interim/gigawords/Event-Timestamp and Message-Authenticator request/response behavior used by the declared MVP.
- RFC 3579 Message-Authenticator validate/calculate and EAP-Message-without-MA discard. EAP **termination** is not included.
- RFC 5080 deterministic bounded duplicate/retransmission behavior.
- Project rows `PRJ-*` for MA discard policy, unknown-client discard, deterministic policy, stable error mapping, accounting idempotency, bounded storage, runtime limits, one-datagram binding, v1/v2 config, TACACS regression, and REST/MCP parity.
- Independent `internal/radius/testclient` codec evidence. Shared-codec loopback is not sufficient.
- Tunneled EAP (PEAP/EAP-TLS), DTLS, RADIUS/1.1, proxying, and persistent accounting stay deferred. Access-Challenge, Identity+EAP-MD5, RADIUS MS-CHAP, DAC CoA, optional inbound DAS, RadSec TLS 1.3, operator dictionaries, and named `Cisco-AVPair` (vendor 9 type 1) have ADRs and tests; IOL skip is not PASS. `conformance_status` stays `partial`.

Do not set RADIUS `conformance_status` to `pass` or expose a complete-RADIUS badge while any MVP row is `NOT_STARTED` or lacks evidence. UDP ports **1812** (access), **1813** (accounting), and **3799** (DAS, default off) plus TCP **2083** (RadSec, default off) are the RADIUS lab ports when listeners are enabled; they stay off the public internet. Inbound :3799 mutates the in-memory session index only and never forwards to a NAS.

### 2.8 Fail closed and preserve old state on invalid change

- Unknown clients are rejected.
- Invalid or ambiguous client matches are rejected during configuration compilation.
- Unknown users and unmatched authorization rules default to deny.
- Invalid configuration reloads leave the previous effective snapshot active.
- Invalid runtime mutations do not partially apply.
- Unsupported or malformed protocol options receive the RFC-defined failure/error behavior and session handling.
- Missing authorization scope denies the operation.
- RADIUS exception (documented, not a general waiver): Accounting-Request with no Acct-Session-Id **and** no NAS-IP/NAS-Identifier is fail-open-to-ack (send Accounting-Response) and sample-capped for ring append so the shared event ring cannot be filled unbounded. See [ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md).

### 2.9 Protect secrets everywhere

Never return, log, trace, export, include in events, or expose in UI state:

- TACACS shared secrets.
- RADIUS shared secrets and unhidden User-Password material.
- clear-equivalent CHAP or MS-CHAP secrets.
- passwords or password-change values.
- API bearer token values after their one-time creation response.
- TLS private keys.
- session cookies.

Secret-bearing types must not implement unconstrained string formatting. Structured logging must use explicitly redacted views.

### 2.10 Preserve determinism

Given the same effective configuration, runtime overlay, request, and clock-independent inputs, the same decision must result.

- Sort all externally returned collections deterministically.
- Define and test client-match precedence.
- Define and test group/rule ordering.
- Avoid map iteration order in policy evaluation and API output.
- Use injectable clocks and random sources in tests.
- Keep policy traces stable enough for golden tests.

## 3. Required workflow for every task

1. Identify the task ID in `docs/TASKS.md` or add one.
2. Identify affected conformance and parity rows.
3. Write or update the relevant acceptance tests first.
4. Implement the smallest coherent vertical slice.
5. Add negative and concurrency tests.
6. Add or update benchmarks when the hot path is affected.
7. Regenerate schemas and generated documentation.
8. Update operator and design documentation.
9. Run all required local checks.
10. Record acceptance evidence and mark only proven checklist items complete.
11. After every push, PR update, merge, or tag, monitor GitHub Actions until green (§9). On failure, fix and harden; do not walk away.

## 4. Definition of done

A task is done only when:

- Production code is complete and contains no placeholder behavior.
- The public contract is represented in typed schemas.
- Regression and acceptance tests pass.
- `go test -race ./...` passes for applicable packages.
- Frontend type checking, linting, tests, and production build pass.
- Fuzz seed corpus tests pass.
- Relevant benchmarks have a recorded result.
- REST/MCP parity checks pass.
- Secret-redaction tests pass.
- Configuration and documentation are current.
- No TODO remains without a linked task ID, owner, and disposition.
- CI for the change’s ref is green (`ci-gate` on pull requests and `main`; on tags, `ci` and `release`).

## 5. Testing commands expected in CI

The final repository may wrap these commands in `make`, `task`, or another checked-in runner, but equivalent coverage is mandatory.

```bash
go test ./...
go test -race ./...
go vet ./...
staticcheck ./...
go test ./internal/tacacs/... -run 'Fuzz' -fuzztime=0
go test ./internal/radius/... -run 'Fuzz' -fuzztime=0
make check-registries

go test -bench=. -benchmem ./internal/tacacs/... ./internal/radius/... ./internal/policy/... ./internal/state/...

npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run lint
npm --prefix web test
npm --prefix web run build
npm --prefix web run test:e2e

docker build --check --target runtime .
docker build --check --target runtime-ubuntu .
docker build --check --target runtime-rocky .
docker compose -f deployments/compose/compose.yaml config
make lab-test
make cisco-lab   # optional; SKIP exit 0 without TACLAB_IOL_IMAGE
make check-release-notes
# equivalent one-shot after tools/labgen (high host ports via compose.lab-test.yaml):
# docker compose -f deployments/compose/compose.yaml -f deployments/compose/compose.lab-test.yaml \
#   up --abort-on-container-exit --exit-code-from integration-tests
```

Long-running fuzzing, load tests, and full vendor interoperability may run in scheduled or release pipelines, but their seed corpora and smoke variants must run on every change.

## 6. Change-specific instructions

### 6.1 Protocol code

- Use bounded reads before allocation.
- Validate header and body lengths independently.
- Preserve raw packet fixtures for regressions.
- Do not recover from malformed state in a way that violates required session termination.
- Add fuzz seeds for every fixed parser or state-machine defect.
- Add race tests for single-connect multiplexing and shutdown.

### 6.2 Policy code

- Compile regexes and selectors during snapshot compilation, never per request.
- Preserve AV-pair order and duplicates.
- Do not use the client-reported `authen_method` field as a trusted authorization input.
- Emit a stable explanation trace without exposing secrets.
- Default deny when no rule matches.

### 6.3 API code

- Use the common operation registry.
- Reject unknown JSON fields for mutation requests unless a versioned compatibility rule says otherwise.
- Use cursor pagination and deterministic ordering.
- Enforce size limits before decoding large bodies.
- Return common error codes, not adapter-specific messages only.
- Mark all secret fields write-only in OpenAPI and omit them from MCP outputs.

### 6.4 Frontend code

- Use generated API types and clients.
- Do not duplicate server-side policy evaluation.
- Treat all server strings as untrusted content.
- Display `CONFIG`, `RUNTIME`, or `OVERRIDE` source badges.
- Display the active revision and stale-write conflicts.
- Update from server events rather than polling aggressively.
- Provide accessible keyboard operation, labels, focus states, and error summaries.

### 6.5 Deployment code

- Run non-root.
- Use a read-only root filesystem and explicit writable tmpfs paths.
- Load secrets from files or a secret provider, not ordinary environment variables by default.
- Do not bake example secrets into images.
- Expose high container ports and map well-known host ports in Compose.
- Maintain a single replica while runtime state is memory-only.
- Cisco device interop uses Containerlab `cisco_iol` only (`make cisco-lab`). Do not add GNS3 or dynamips. Do not vendor IOL/refplat images. A skip when the operator image is absent is not Cisco PASS.

## 7. Prohibited shortcuts

Do not:

- Implement MCP by proxying to REST over localhost.
- Implement REST by invoking MCP tools internally.
- Store a second mutable copy of users or policies in an adapter.
- use UI-only validation as the enforcement layer.
- silently ignore unsupported TACACS fields or invalid accounting flag combinations.
- return success for accounting before the record is accepted by the configured in-memory record sink.
- write runtime changes back into the source configuration file.
- add persistent storage without an architecture decision and explicit opt-in configuration.
- expose a “complete” badge while conformance rows are unverified.
- claim complete RADIUS while `R65-*` / `R66-*` / `R69-*` / `R79-*` / `R80-*` / `PRJ-*` MVP rows are `NOT_STARTED` or lack evidence.
- disable race, fuzz, security, or interoperability tests to make CI pass.
- tag a release and walk away while tag CI is red or still running.
- publish a GitHub Release without a CHANGELOG section that lists **all high-level changes since the previous tag**, or without Ubuntu and Rocky image builds.
- treat `git log` alone as the release notes. Commits are a supplement; operators need the CHANGELOG delta.

## 8. Architecture decision records

Create an ADR for decisions that alter:

- protocol compatibility.
- TLS authentication methods.
- state precedence or persistence.
- authorization rule semantics.
- REST/MCP parity policy.
- public configuration schema.
- security boundaries.
- deployment topology.
- performance budgets.

An ADR must include context, decision, alternatives, consequences, compatibility impact, migration, test impact, and documentation impact.

## 9. CI watch and releases

These rules apply to every agent (main session and subagents) after a push, PR update, merge, or git tag.

### 9.1 Always monitor CI

1. Identify the GitHub Actions run for the ref you just changed (`gh run list --branch <ref>` or the tag). Official `gh` only (`cli/cli`).
2. Wait for completion. Do not declare the change done while that run is queued, in progress, or red.
3. Required green jobs on `main` and on pull requests: `lint-test-build`, `compose-lab`, `govulncheck`, `gitleaks`, `ci-gate`.
4. On `main` pushes that touch `site/` or `.github/workflows/pages.yml`, also wait for the `pages` workflow. `GITHUB_TOKEN` cannot create a Pages site; do not set `configure-pages` `enablement: true`. See [docs/MAINTENANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MAINTENANCE.md) §GitHub Pages.
5. On tags (`v*`), also wait for the `release` workflow: release notes, Ubuntu image, Rocky image, GitHub Release.
6. On failure: read the failed job logs, fix the root cause, and **harden** so the same class of failure cannot recur (pin, allowlist, timeout, test, or workflow change). Push and watch again.
7. After a release tag, a red run is a **release blocker**. Cut a fix commit and either move the tag after the new run is green or publish a patch tag. Do not leave a published tag pointing at a failing tree.

### 9.2 Every release must include all high-level changes between versions

Move every `[Unreleased]` item into `## [<version>] — YYYY-MM-DD` before tagging. The CHANGELOG section is the **operator-facing delta since the previous tag** (or since the start of the repository for the first tag). It must cover, when they happened:

- new or changed behavior (protocol, REST, MCP, UI, lab, CLI)
- security and toolchain fixes
- breaking changes and residual limits
- interop / image / deploy changes
- anything a client or operator would notice

Do not tag with an empty section, “see git log”, or a partial list. `make release-notes` appends `git log` as a **supplement**; it does not replace the high-level section.

A version is not released until all of the following exist for that tag:

| Deliverable | How |
|---|---|
| High-level changes between this tag and the previous tag | A complete `## [<version>]` section in [CHANGELOG.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/CHANGELOG.md) **and** `make release-notes` (that section plus `git log`). The GitHub Release body is that file. |
| Ubuntu 24.04 image | `make image-ubuntu` → `ghcr.io/hilather/go-lab-tacacs-mcp:<tag>-ubuntu` |
| Rocky Linux 9 image | `make image-rocky` → `ghcr.io/hilather/go-lab-tacacs-mcp:<tag>-rocky` |
| Default (distroless) image | `make image` → `ghcr.io/hilather/go-lab-tacacs-mcp:<tag>` |

Do not ship a tag that only has notes or only has one distro. Operators who run Rocky or Ubuntu hosts must be able to pull a matching variant from the same release.

### 9.3 After a new release, CI must pass; failures harden CI

Tagging is not the end of the job. After `git push origin vX.Y.Z`:

1. Wait for **both** tag workflows: `ci` (`ci-gate` and its jobs) and `release` (notes + Ubuntu + Rocky + GitHub Release).
2. Do not declare the release done while either run is queued, in progress, or red.
3. If CI fails: read the failed job logs, find the root cause, fix the product **or** the workflow, and **harden** so the same class of failure cannot recur (pin, checksum, timeout, missing test, flaky gate, or docs check). Push the fix.
4. A red tag is a **release blocker**. Move the tag onto a green commit or publish a patch tag. Do not leave a published `v*` pointing at a failing tree.

Release procedure is in [docs/MAINTENANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MAINTENANCE.md) §Release.
