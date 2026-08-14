# TacLab Implementation Backlog and Agent Task Lists

Status: executable implementation plan  
Architecture: all-in-one Go backend with React and TypeScript frontend  
Last updated: 2026-08-14

## 1. How agents must use this backlog

This file is the implementation sequence and acceptance checklist. It is not permission to ignore the contracts in `AGENTS.md`, `DESIGN.md`, `ARCHITECTURE.md`, `TACACS_CONFORMANCE.md`, `RADIUS_CONFORMANCE.md`, `API_PARITY.md`, `CONFIGURATION.md`, `TESTING_AND_BENCHMARKS.md`, or `LAB_DEPLOYMENT.md`.

RADIUS work uses stable pack task IDs `RAD-*` (section 22). Do not invent a parallel RADIUS numbering scheme.

For every task:

1. Read the linked contracts and applicable protocol rows.
2. State the intended behavior and affected operation IDs before coding.
3. Implement through the approved package boundaries.
4. Add or update regression tests.
5. Add, update, or rerun relevant benchmarks.
6. Keep REST and MCP behavior in parity through the shared operation layer.
7. Update documentation and generated artifacts in the same change.
8. Run the task's acceptance commands and record results.
9. Do not mark a task complete with disabled tests, undocumented exceptions, or unreviewed conformance gaps.

### 1.1 Task status legend

```text
[ ] Not started
[~] In progress
[!] Blocked; blocker and owner must be recorded
[x] Complete; acceptance evidence linked
```

### 1.2 Required task evidence

Each completed task should link or attach:

- Implementation change/commit.
- Test names and result summary.
- Regression test associated with each fixed defect.
- Benchmark before/after result when applicable.
- Updated documentation and generated schema diff.
- REST/MCP parity disposition.
- Security and secret-handling review notes.
- Conformance row IDs affected.

### 1.3 Change template

Agents should use this checklist in issue and pull-request descriptions:

```markdown
## Behavior

## Operation IDs / protocol rows

## Implementation

## REST/MCP parity

## Regression tests

## Benchmarks

## Security and secrets

## Documentation

## Acceptance evidence
```

## 2. Delivery strategy

### 2.1 Critical path

```text
P0 Governance and repository
 -> P1 Protocol decision spike
 -> P2 Domain/config/state
 -> P3 TACACS codec
 -> P4 Connection server
 -> P5 Authentication
 -> P6 Authorization
 -> P7 Accounting
 -> P8 Secure TACACS/TLS
 -> P9 Shared operations/auth
 -> P10 REST
 -> P11 MCP
 -> P12 React UI
 -> P13 Hardening/observability
 -> P14 Container lab
 -> P15 Conformance/performance/interoperability
 -> P16 Release/documentation
```

### 2.2 Parallel lanes

After P2 stabilizes, agents may work in parallel when package interfaces are agreed:

- Protocol lane: P3-P8.
- Control-plane lane: P9-P11.
- Frontend lane: P12 after REST schemas are usable.
- Quality lane: fixtures, fuzzing, benchmarks, CI, and secret-canary framework throughout.
- Deployment lane: P14 skeleton early, final acceptance after all listeners and APIs exist.

Parallel work must not create duplicate domain models or API-only business logic.

## 3. Milestone P0 - Governance, repository, and reproducible tooling

### P0.1 Create repository skeleton

**Depends on:** none  
**Output:** package structure matching `ARCHITECTURE.md`

- [x] Create `cmd/taclabd` and internal package directories.
- [x] Create `web` workspace with React and TypeScript.
- [x] Create `api`, `configs`, `testdata`, `deployments`, `docs`, and `tools` directories.
- [x] Add root build commands through `Makefile`, `justfile`, or equivalent documented runner.
- [x] Add license, contribution, security-reporting, and code-of-conduct files appropriate to the repository.
- [x] Copy this implementation packet into the repository root/docs tree.

**Tests and evidence**

- [x] Clean checkout can run a no-op backend test and frontend test.
- [x] Repository path checks ensure generated files go to intended directories.

**Benchmarks**

- [x] Add benchmark command placeholders that fail clearly until benchmark packages exist; do not report false success.

**Documentation**

- [x] Root README links to all implementation contracts and build prerequisites.

### P0.2 Pin toolchains and dependencies

**Depends on:** P0.1

- [x] Pin the Go toolchain version.
- [x] Pin Node.js and package-manager versions.
- [x] Commit the frontend lockfile.
- [x] Establish dependency-update policy and automated alerts.
- [x] Add deterministic generation tooling with pinned versions.
- [x] Record the MCP specification and official Go SDK version baseline.

**Acceptance**

- [x] Local and CI builds report identical dependency graphs from a clean checkout.
- [x] Tool version output is captured in CI artifacts.

### P0.3 Establish engineering checks

**Depends on:** P0.1

- [x] Add Go formatting, vet/static analysis, tests, race tests, fuzz-seed tests, and benchmark smoke commands.
- [x] Add TypeScript type checking, linting, unit tests, accessibility checks, and production build.
- [x] Add Markdown link/style checks that do not rewrite normative protocol language.
- [x] Add generated-file drift detection.
- [x] Add secret scanning and dependency vulnerability scanning.
- [x] Add an artifact-retention policy for test reports, benchmarks, SBOM, and evidence.

**Acceptance**

- [x] A deliberately malformed Go file, TypeScript type error, stale generated file, and test secret are each caught in dedicated CI validation.

### P0.4 Create specification traceability registry

**Depends on:** P0.1

- [x] Encode TACACS conformance row IDs in a machine-readable file.
- [x] Encode canonical operation IDs and REST/MCP exposure metadata in `api/operations.yaml` or typed Go source.
- [x] Generate human-readable conformance and parity tables where practical.
- [x] Add CI checks for duplicate IDs, missing dispositions, and undocumented operations.

**Regression tests**

- [x] Add fixtures proving missing REST or MCP bindings fail parity checks.
- [x] Add fixtures proving unreferenced mandatory conformance rows fail release validation.

**Documentation**

- [x] Document generation and review workflow in `API_PARITY.md` and `TACACS_CONFORMANCE.md`.

### P0.5 Publish the static project site on GitHub Pages

**Depends on:** P0.3

- [x] Deploy `site/` from `.github/workflows/pages.yml` using GitHub Actions as the Pages source.
- [x] Enable the Pages site once as a repo admin (`build_type=workflow`). `GITHUB_TOKEN` cannot create it.
- [x] Reject `configure-pages` `enablement: true` in `tools/check-pages-workflow.sh`.
- [x] Fail the deploy job with an actionable message if Pages is missing or not `workflow`.

**Acceptance**

- [x] `make docs-check` rejects a pages workflow that sets `enablement: true`.
- [x] Pages deploy no longer depends on `GITHUB_TOKEN` creating the site.

**Regression tests**

- [x] `tools/check-hooks.sh` plants `enablement: true` and expects the checker to fail.

**Documentation**

- [x] [MAINTENANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/MAINTENANCE.md) records the one-time admin enable command.

### P0 exit gate

- [ ] Clean backend/frontend build works.
- [ ] CI catches source, test, schema, docs, and secret failures.
- [ ] Toolchains and dependency locks are reproducible.
- [x] Conformance and operation registries have machine-readable owners.

## 4. Milestone P1 - TACACS protocol implementation decision spike

### P1.1 Build candidate inventory

**Depends on:** P0

- [x] Evaluate maintained Go TACACS codec/server packages and internal implementation scope.
- [x] Record license, maintenance activity, RFC 8907 coverage, RFC 9887 readiness, fuzz/race posture, API extensibility, and known interoperability evidence.
- [x] Reject packages that force policy or credential models into transport code.
- [x] Reject packages whose license or transitive dependencies are unacceptable.

**Documentation**

- [x] Create an architecture decision record selecting reuse, fork, or internal codec implementation.

### P1.2 Implement black-box spike harness

**Depends on:** P1.1

- [ ] Create a small server adapter and independent test client/harness.
- [x] Exercise packet encode/decode, sequence progression, legacy obfuscation, session IDs, and single-connect.
- [ ] Exercise every authentication type required for 1.0.
- [ ] Exercise authorization and accounting packet families/statuses.
- [x] Inject malformed lengths, unsupported versions, truncated data, and invalid sequences.
- [x] Run with the race detector and initial fuzz corpus.

**Benchmarks**

- [x] Benchmark header/body encode/decode and legacy body transform for representative packet sizes.

The spike under `tools/spike` covers header layout, sequence wrap, single-connect flag inspection, and RFC 8907 §4.5 obfuscation. Production header, body families, and pad live in `internal/tacacs/codec`; the independent copy is `internal/tacacs/testclient/codec`. There is no listener or `net.Conn` adapter yet.

### P1.3 Decide and isolate the adapter boundary

**Depends on:** P1.2

- [x] Select the implementation approach using measured evidence.
- [x] Decided: in-tree package `internal/tacacs/codec`; no third-party TACACS types in AAA, policy, operations, or API packages.
- [x] Define the project-owned codec/connection Go interface (encode/decode types).
- [x] Document patches or upstream contributions required for conformance.
- [x] Pin exact dependency versions or fork commit.

No library is pinned. The typed codec API lands with P3. An override would require a new ADR, an isolated encode/decode surface, and a Go-version decision. See [ADR 0007](decisions/0007-codec-approach.md). Evaluation revisions of the rejected candidates are recorded in that ADR.

**Acceptance**

- [x] Every mandatory protocol feature is either demonstrated or has a task and conformance row owner.
- [x] No README claim from a dependency is accepted as conformance evidence without an executable test.

Transport adapters remain owned by P4 and the T89/T98 rows.

### P1 exit gate

- [x] Protocol approach ADR approved.
- [x] Independent spike evidence exists.
- [x] Initial codec benchmarks and fuzz corpus are checked in.
- [x] All known feature gaps appear in this backlog and conformance matrix.

## 5. Milestone P2 - Domain model, configuration, and immutable state

### P2.1 Implement core domain types

**Depends on:** P1 boundary decision

- [x] Implement stable IDs and metadata for users, groups, clients, tokens, rules, listeners, and revisions.
- [x] Implement ordered AV pairs preserving separator, duplication, and order.
- [x] Implement authentication method and service enums without lossy string fallbacks.
- [x] Keep secret-bearing types separate from response/view types.
- [x] Add constructors that enforce local invariants.

**Regression tests**

- [x] Round-trip and equality tests preserve every significant field.
- [x] Secret types cannot be serialized through normal API encoders.

**Benchmarks**

- [ ] Benchmark cloning/compilation of representative domain collections only if used on publication paths.

### P2.2 Implement strict YAML loader

**Depends on:** P2.1

- [x] Implement schema version enforcement.
- [x] Reject unknown fields, duplicate keys, aliases/anchors, multiple documents, invalid UTF-8, and oversized input.
- [x] Produce stable path-qualified error codes.
- [x] Resolve typed file secret references.
- [x] Parse global and per-client legacy shared-secret policy/lifecycle metadata.
- [x] Implement safe default values explicitly.

**Regression tests**

- [x] Golden valid configurations.
- [x] One regression fixture per rejection class.
- [x] Secret error messages pass canary tests.

**Benchmarks**

- [x] Benchmark small, standard, and maximum reference configuration parsing.

### P2.3 Implement cross-object validation

**Depends on:** P2.2

- [x] Validate user-to-group, client-to-group, listener, TLS, credential-method, policy, and token-scope references.
- [x] Reject ambiguous client matching.
- [x] Validate command regexes and compile them once.
- [x] Validate object and string-size limits before expensive work.
- [x] Validate required credential material for enabled authentication methods.
- [x] Enforce configurable legacy shared-secret minimum length and character-class policy while accepting keys of at least 32 characters without truncation.
- [x] Reject configured known-weak values without echoing them.
- [x] Detect shared-secret reuse through process-local keyed HMAC fingerprints and emit a bounded warning when configured.
- [x] Validate rotation metadata and compute `current`, `due_soon`, `overdue`, or `unknown` using an injectable clock.

**Regression tests**

- [x] Table-driven tests cover every machine-readable validation code.
- [x] Secret-policy tests cover short, weak, 32-plus-character, duplicate, due-soon, overdue, unknown, and strict-profile cases.

### P2.4 Implement baseline, overlay, tombstone, and revision store

**Depends on:** P2.3

- [x] Load immutable baseline state.
- [x] Implement complete-object runtime replacement.
- [x] Implement runtime-only creation.
- [x] Implement tombstones for baseline objects.
- [x] Implement expected-revision conflict checks.
- [x] Implement atomic reset.
- [x] Track source/shadow metadata without placing timestamps in policy ordering.

**Regression tests**

- [x] Create/update/delete/shadow/reset tests for every object kind.
- [x] Concurrent stale revision tests.
- [x] Restart reconstruction tests using a fresh store.

**Benchmarks**

- [x] Benchmark overlay mutation and snapshot rebuild at reference sizes.

### P2.5 Implement compiled immutable snapshots

**Depends on:** P2.4

- [x] Compile client CIDR/certificate match indexes.
- [x] Compile user and group indexes.
- [x] Compile policy rule matchers.
- [x] Precompute safe credential capability metadata.
- [x] Precompute legacy shared-secret lifecycle status and deduplicated warning records without retaining serializable or exportable fingerprints.
- [x] Publish through an atomic pointer or equivalent lock-light read path.
- [x] Keep prior snapshot alive for in-flight sessions.

**Regression tests**

- [x] Readers observe either complete old or complete new snapshots, never partial state.
- [x] Invalid candidate publication preserves old state.
- [x] Race detector covers concurrent read/mutate/reload tests.

**Benchmarks**

- [x] Lookup benchmarks for user, client, group, and policy indexes.
- [x] Snapshot compile/publication benchmarks.

### P2.6 Implement reload and rebase

**Depends on:** P2.5

- [x] Implement validate-only and reload operations at service level.
- [x] Implement overlay `rebase` and `reset` behavior.
- [x] Reject invalid rebase atomically.
- [ ] Emit sanitized reload events.
- [ ] Add signal integration without placing reload logic in signal handlers.

**Documentation**

- [x] Keep `CONFIGURATION.md` example and field reference synchronized.

### P2 exit gate

- [x] All configuration rules and overlay semantics have tests.
- [x] Atomic snapshot race tests pass.
- [x] Config compile benchmarks are recorded.
- [x] No secret value can be serialized or logged by the state packages.

## 6. Milestone P3 - TACACS codec and packet conformance

### P3.1 Implement/complete common header codec

**Depends on:** P1, P2 types

- [x] Parse and encode version, type, sequence number, flags, session ID, and body length.
- [x] Enforce body and allocation limits before allocation.
- [x] Preserve unsigned widths and network byte order.
- [x] Distinguish unsupported version/type from malformed packet.
- [x] Implement stable errors suitable for connection policy and metrics.

**Tests**

- [x] Golden packets for every packet family.
- [x] Boundary lengths: zero, maximum accepted, and one above maximum.
- [x] Truncation at every header byte.
- [x] Fuzz target with persistent regression corpus.

**Benchmarks**

- [x] Header parse/encode for valid and rejected packets.

### P3.2 Implement legacy packet-body transform

**Depends on:** P3.1

- [x] Implement RFC 8907 body transformation exactly.
- [x] Handle empty and multi-block bodies.
- [ ] Apply transform only for the legacy listener and appropriate flag state.
- [ ] Never use a TLS PSK or credential secret as the legacy shared secret.

The codec exposes `Obfuscate(sessionID, version, seq, key, body)` and takes a raw key only. Listener flag policy and typed-secret wiring remain with the legacy adapter.

**Tests**

- [x] Published/independently generated vectors.
- [x] Wrong-secret behavior.
- [x] Round-trip property tests that do not substitute for independent vectors.
- [x] Fuzzing for lengths and block boundaries.

**Benchmarks**

- [x] Representative 64 B and 1 KiB bodies (`BenchmarkLegacyObfuscate_64B`, `BenchmarkLegacyObfuscate_1KiB`).
- [ ] Representative 32 B, 256 B, 4 KiB, and maximum-safe bodies.

### P3.3 Implement authentication packet family

**Depends on:** P3.1

- [x] Encode/decode START, CONTINUE, and REPLY fields.
- [x] Enforce per-packet field lengths and total body consistency.
- [x] Preserve data/message bytes without unsafe string assumptions.
- [x] Validate action/type/service/version combinations in the protocol layer.

**Tests**

- [x] Golden packet for every action, type, service, and reply status.
- [x] Malformed offset/length and continuation flag cases.

### P3.4 Implement authorization packet family

**Depends on:** P3.1

- [x] Encode/decode REQUEST and RESPONSE.
- [x] Preserve argument count/order and AV separators.
- [x] Support PASS_ADD, PASS_REPL, FAIL, and ERROR statuses.
- [x] Validate length arrays without overflow.

**Tests and benchmarks**

- [x] Golden cases for empty, duplicate, mandatory, and optional attributes.
- [x] Benchmark representative and maximum argument lists.

### P3.5 Implement accounting packet family

**Depends on:** P3.1

- [x] Encode/decode REQUEST and REPLY.
- [x] Preserve flags and arguments.
- [x] Validate START/STOP/WATCHDOG flag semantics.
- [x] Support SUCCESS and ERROR replies as specified.

**Tests**

- [x] Golden records for each valid action.
- [x] Invalid zero/multiple action flag cases.

### P3.6 Implement sequence/version/session validation helpers

**Depends on:** P3.3-P3.5

- [x] Centralize packet sequence state machines by session type.
- [x] Enforce client/server odd/even sequence behavior.
- [x] Enforce permitted minor versions by authentication flow.
- [x] Detect wrap and excessive continuation rounds.

**Tests**

- [x] Full valid and invalid sequence tables.
- [x] Fuzz state-machine transitions.

### P3 exit gate

- [ ] All codec conformance rows have automated evidence.
- [ ] Fuzz corpus is stable under continuous runs.
- [ ] Codec benchmarks have baselines.
- [ ] Independent fixture generation is documented.

## 7. Milestone P4 - Connection server and legacy listener

### P4.1 Implement listener lifecycle

**Depends on:** P2 snapshot, P3 codec

- [x] Bind configured addresses.
- [x] Apply connection limits and timeouts.
- [x] Support graceful drain and shutdown.
- [x] Report listener readiness and runtime failures.
- [x] Keep legacy and TLS listeners structurally separate while sharing the session engine.

**Tests**

- [x] Bind failure, shutdown, timeout, and readiness transitions.
- [x] Leak tests for repeated start/stop.

### P4.2 Implement client matching

**Depends on:** P2 indexes, P4.1

- [x] Match transport and source IP using deterministic ordering.
- [x] Select legacy shared secret only after a unique client match.
- [x] Fail closed for unknown or ambiguous clients.
- [x] Store sanitized connection identity for events.

**Tests and benchmarks**

- [x] IPv4/IPv6, overlapping CIDRs, priority, and unknown client cases.
- [ ] Benchmark client matching at maximum reference client count.

### P4.3 Implement connection/session dispatcher

**Depends on:** P3, P4.2

- [x] Read exact headers and bounded bodies.
- [x] Decode legacy body after client selection.
- [x] Dispatch by packet type and session ID.
- [x] Isolate per-session state.
- [x] Apply cancellation on disconnect and shutdown.
- [x] Prevent one connection from monopolizing worker resources.

**Regression tests**

- [x] Interleaved session IDs.
- [x] Duplicate session ID while active.
- [x] Partial reads/writes and abrupt disconnects.
- [x] Slowloris and timeout behavior.

**Benchmarks**

- [x] End-to-end in-memory connection dispatch without credential cost.

### P4.4 Implement single-connect

**Depends on:** P4.3

- [x] Negotiate and reflect the single-connect flag correctly.
- [x] Keep eligible connections open between sessions.
- [x] Support concurrent sessions safely.
- [x] Enforce idle, lifetime, and session-count bounds.
- [x] Close or reject invalid flag/sequence behavior predictably.

**Tests**

- [x] Negotiated and non-negotiated cases.
- [x] Multiplexed authentication, authorization, and accounting sessions.
- [x] Race, leak, timeout, and forced-close cases.

**Benchmarks**

- [x] Connection-per-session versus single-connect throughput and allocations.

### P4.5 Implement protocol-safe error strategy

**Depends on:** P4.3

- [x] Map parser, state, policy, internal, timeout, and resource errors to allowed reply/close behavior.
- [x] Avoid oracle-like detail on the wire.
- [x] Emit stable internal error codes with redacted context.
- [x] Define which malformed inputs require immediate connection close.

**Documentation**

- [x] Update error handling tables in `DESIGN.md` and `TACACS_CONFORMANCE.md`.

### P4 exit gate

- [x] Legacy listener can safely carry all packet families to stub handlers.
- [x] Single-connect race and load tests pass.
- [x] Source matching and body transformation are correct.
- [ ] Connection/resource benchmarks are recorded.

## 8. Milestone P5 - Authentication service completeness

### P5.1 Implement credential service

**Depends on:** P2 domain/state

- [x] Verify configured slow password verifiers for ASCII/PAP.
- [x] Handle runtime plaintext submission by immediately deriving a verifier.
- [x] Store challenge secret material only in protected process memory.
- [x] Verify ENABLE credentials separately.
- [x] Return capability metadata without secret data.
- [x] Use constant-time comparisons where applicable.

**Tests**

- [x] Correct/incorrect/missing/disabled/expired/restricted credentials.
- [x] Secret canaries and error uniformity.

**Benchmarks**

- [x] Password verification benchmark with documented cost parameters.
- [x] Challenge-response calculation benchmarks.

Evidence: `internal/credentials` (Argon2id PHC, CHAP/MS-CHAP, ENABLE, token digests), [ADR 0002](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0002-password-kdf.md). Protocol conversation tests remain P5.2–P5.7.

### P5.2 Implement ASCII login conversation

**Depends on:** P3 auth packets, P4 dispatcher, P5.1

- [x] Handle GETUSER/GETPASS/GETDATA and CONTINUE exchanges as required.
- [x] Bound rounds and message/data sizes.
- [x] Handle abort flag and disconnect.
- [x] Avoid username enumeration in prompts and failures.
- [x] Produce PASS, FAIL, ERROR, and RESTART only under specified conditions.

**Tests**

- [x] Success, wrong password, unknown user, disabled user, abort, timeout, malformed continuation, excessive rounds, and restart scenarios.
- [x] Independent client interoperability.

### P5.3 Implement PAP

- [x] Validate action/type/version/service combinations.
- [x] Verify supplied password through the credential service.
- [x] Handle empty and oversized fields safely.
- [x] Return standards-compliant statuses.

**Tests/benchmarks/docs**

- [x] Positive, negative, malformed, and unavailable-verifier tests.
- [ ] End-to-end PAP benchmark excluding and including verifier cost (KDF benches stay under `internal/credentials`).
- [x] Update method capability documentation.

### P5.4 Implement CHAP

- [x] Parse challenge/identifier/response data exactly.
- [x] Calculate expected response using challenge secret material.
- [x] Reject unavailable challenge secret without fallback to a login hash.
- [x] Bound all fields and compare safely.

**Tests**

- [x] Independent known vectors, wrong response, malformed length, altered challenge, and missing-secret cases.

### P5.5 Implement MS-CHAP v1

- [x] Implement with vetted cryptographic primitives and independent vectors.
- [x] Validate exact wire data sizes.
- [x] Separate protocol errors from credential failure in internal events while keeping wire behavior safe.

**Tests/benchmarks**

- [x] Known vectors and all malformed boundaries.
- [x] Calculation benchmark.

### P5.6 Implement MS-CHAP v2

- [x] Implement peer/authenticator challenge processing and response validation.
- [x] Use independent vectors.
- [x] Handle username canonicalization exactly as selected in the design ADR.

**Tests/benchmarks**

- [x] Known vectors, altered username/challenges/response, malformed sizes, and missing secret.
- [x] Calculation benchmark.

### P5.7 Implement ENABLE

- [x] Match service/action semantics.
- [x] Verify separate enable credential.
- [x] Apply client and user restrictions.
- [x] Avoid implicit reuse of login or shared secret unless explicitly modeled and documented.

**Tests**

- [x] Success/failure/missing verifier/restriction/version cases. ENABLE START goldens with `authen_type=ASCII` and `authen_type=PAP` both enter ENABLE.

### P5.8 Implement ASCII password change

- [x] Implement the complete state machine.
- [x] Verify current credential before accepting a new password.
- [x] Derive and atomically publish a runtime verifier override.
- [x] Preserve baseline config and reset semantics.
- [x] Define behavior when only challenge credentials exist.
- [x] Never log old or new password.

**Tests**

- [x] Success, incorrect old password, policy failure, interrupted conversation, compile failure rollback, revision conflict, and restart restoration.
- [ ] REST/MCP/UI state views reflect capability change without secrets.

**Benchmarks**

- [x] Password derivation cost and state publication separately.

### P5.9 Implement authentication policy restrictions

- [x] Enforce allowed method per client, including a challenge-response-only profile.
- [x] Recognize every RFC-defined authentication service code and reject invalid action/type/service combinations without inventing undocumented flows.
- [x] Enforce enabled state, client restrictions, and validity windows.
- [x] Warn when non-challenge methods are enabled according to the configured security profile. 1.0: operator docs + ADR-0012 (`DISPOSITIONED_SHOULD`); challenge-only profile still RESTARTs ASCII/PAP.
- [x] Define normalization and exact username lookup behavior.
- [x] Emit consistent audit events.

### P5 exit gate

- [x] Every mandatory authentication conformance row passes (YAML `PASS` + evidence; `make check-registries -release`).
- [x] Every method has independent vectors/interoperability evidence (testclient + goldens; device NOS skipped).
- [ ] Password-change rollback and restart behavior pass.
- [ ] Authentication benchmarks and secret-canary tests pass.

## 9. Milestone P6 - Authorization and policy engine

### P6.1 Implement service authorization evaluator

**Depends on:** P2 compiled policy, P3 authorization, P4 dispatcher

- [x] Resolve user and ordered groups.
- [x] Match service, protocol, client, and optional contextual constraints.
- [x] Implement the complete RFC 8907 common authorization argument dictionary and value encodings while retaining arbitrary vendor attributes.
- [x] Validate numeric sizes before conversion, Booleans, IPv4/IPv6 text, UTC/timezone behavior, and empty values.
- [x] Preserve input AV order and separators.
- [x] Compute PASS_ADD or PASS_REPL output intentionally.
- [x] Default deny on no permit.
- [x] Return a machine-readable policy trace.

**Tests and benchmarks**

- [x] Permit/deny/no-match/error, duplicate attributes, optional/mandatory attributes, and group priority cases.
- [x] Benchmark typical and worst-case service rule evaluation.

### P6.2 Implement command authorization evaluator

- [x] Parse `cmd` and ordered `cmd-arg` attributes without shell execution.
- [x] Match exact/regex command and argument rules.
- [x] Apply deterministic user/group/rule order.
- [x] Respect explicit deny and default deny behavior.
- [x] Return exact matched source/rule and normalized display command.

**Tests**

- [x] Admin allow-all and readonly scenarios.
- [x] Empty/missing/duplicate command attributes.
- [x] Regex boundary and RE2 behavior.
- [x] Deterministic ordering across runs.

**Benchmarks**

- [x] Hot-path evaluation for 100, 5,000, and configured maximum rules.

### P6.3 Implement AV-pair response builder

- [x] Preserve mandatory versus optional separator semantics.
- [x] Support replacement and addition without map-based loss.
- [x] Reject or report malformed attributes safely.
- [x] Enforce response argument count/size limits.

**Tests**

- [x] Golden PASS_ADD/PASS_REPL responses and vendor fixtures.

### P6.4 Implement policy explanation operation

- [x] Define typed request/result in the operation layer.
- [x] Produce bounded trace steps.
- [x] Redact credentials and sensitive input.
- [x] Use the exact evaluator used by live authorization.
- [x] Expose through parity-equivalent REST and MCP bindings and UI console later.

**Regression tests**

- [x] Live and explain decisions are identical for the same snapshot/request.

### P6.5 Add vendor policy fixtures

- [x] Capture representative shell/command AV pairs from supported lab systems.
- [x] Store sanitized fixtures with provenance notes.
- [x] Add golden decisions and response attributes.
- [x] Do not hard-code vendor names in core policy logic without ADR approval.

### P6 exit gate

- [x] Authorization conformance rows pass.
- [x] Policy trace matches live behavior.
- [x] Worst-case policy benchmark is within the agreed budget.
- [x] Vendor fixtures are data-driven and documented.

## 10. Milestone P7 - Accounting and event pipeline

### P7.1 Implement accounting validation/service

**Depends on:** P3 accounting, P4 dispatcher

- [x] Validate flags and required contextual fields.
- [x] Accept START, STOP, WATCHDOG-no-update, and WATCHDOG-with-update records; ignore arguments on no-update watchdog records as required.
- [x] Implement the complete common accounting argument dictionary and value encodings while retaining arbitrary vendor attributes.
- [x] Preserve AV pairs, accounting-before-authorization argument order, and source metadata.
- [x] Return SUCCESS/ERROR according to protocol state.
- [x] Separate accounting acceptance from downstream observer availability.

**Tests**

- [x] Valid and invalid flag combinations.
- [x] Duplicate/optional/unknown AV pairs.
- [x] Large bounded records and disconnect behavior.

### P7.2 Implement bounded event model and ring buffer

- [x] Define versioned event schemas for authentication, authorization, accounting, config, token, listener, and system events.
- [x] Use bounded memory and explicit drop policy.
- [x] Ensure TACACS hot paths do not block indefinitely.
- [x] Track dropped-event counters without unbounded cardinality.
- [x] Redact all secret-bearing data before enqueue.

**Tests and benchmarks**

- [x] Ordering, wrap, concurrent readers/writers, drop behavior, and race tests.
- [x] Publish/read benchmark under standard and saturated profiles.

### P7.3 Implement stdout JSON event/log sink

- [x] Produce stable structured fields.
- [x] Keep log level separate from audit event acceptance.
- [x] Prevent control characters and oversized fields from corrupting output.
- [x] Add secret-canary and injection tests.

### P7.4 Implement recent-event query and stream operation

- [x] Add canonical operations for paged recent events and bounded streaming/subscription behavior.
- [x] Apply `events:read` authorization.
- [x] Define cursor/revision/drop semantics.
- [x] Add REST and MCP bindings with parity; where transport mechanics differ, normalize logical event content.

`events.subscribe` REST SSE streams redacted bodies (PR-16a) with keepalives and write-deadline opt-out. MCP `subscriptions/listen` is the C8 URI-only notify channel; bodies stay on `events.list`.

### P7 exit gate

- [x] Accounting conformance rows pass.
- [x] Event ring remains bounded under saturation.
- [x] No event sink failure prevents protocol responses indefinitely.
- [x] Event parity and redaction tests pass.

## 11. Milestone P8 - Secure TACACS+ over TLS 1.3

### P8.1 Implement dedicated TLS listener

**Depends on:** P4 common session server

- [x] Bind a port distinct from legacy TACACS; reference mapping is TCP 300 to container 4300.
- [x] Begin TLS immediately after TCP accept.
- [x] Require TLS 1.3 or later; reject older versions.
- [x] Never implement STARTTLS or protocol sniffing/upgrades.
- [x] Pass decrypted TACACS packets to the common session server.

**Tests**

- [x] Plaintext-on-TLS-port and TLS-on-legacy-port negatives.
- [x] TLS version and immediate-handshake behavior.

### P8.2 Implement mutual certificate authentication

- [x] Load server chain/key and client CA bundle through typed secret/config references.
- [x] Require and validate client certificates in the baseline profile.
- [x] Validate certificate paths and configured network-address/SAN identity constraints.
- [x] Support configured chain bundles for deployments isolated from a remote CA.
- [x] Support SNI profile selection and document that the ClientHello name is observable metadata.
- [x] Enforce DNS/IP SAN and wildcard-identity restrictions and warnings.
- [x] Implement selected revocation mechanism and fail behavior.
- [x] Implement the TLS Cached Information Extension or record an approved RFC `SHOULD` disposition with interoperability impact.
- [x] Implement safe TLS 1.3 cipher-policy configuration where the selected stack permits it, or record an approved RFC `SHOULD` disposition.
- [x] Map certificate identity plus source constraints to one client.

**Tests**

- [x] Valid, invalid, expired, future, revoked, wrong-name, wrong-EKU, unknown-CA, missing, and unauthorized-valid certificate cases.
- [x] Certificate rotation/reload behavior.

**Benchmarks**

- [x] Full handshake, resumed handshake if enabled, and post-handshake request throughput.

### P8.3 Enforce TACACS-over-TLS packet rules

- [x] Require the TACACS unencrypted flag state defined for TLS transport.
- [x] Do not apply RFC 8907 body obfuscation over TLS.
- [x] Apply all normal RFC 8907 packet/session checks after decryption.
- [x] Reject invalid flag combinations and cross-transport assumptions.

### P8.4 Reject early data, downgrade, and unsafe resumption

- [x] Disable/reject TLS early data and the `early_data` extension.
- [x] Do not expose a fallback from failed TLS to legacy.
- [x] Make session resumption and ticket lifetime configurable, including zero.
- [x] Verify or disposition revocation checks between ticket issuance and resumption.
- [x] Review ticket reuse/linkability and implement or document client-tracking mitigations.
- [ ] Keep listener errors and metrics explicit by transport.
- [x] Add security-negative tests and resumed-handshake tests.
- [ ] Add packet-capture evidence.

### P8.5 Optional TLS authentication modes disposition

- [x] Decide external PSK support for the target release.
- [x] Decide raw-public-key support for the target release.
- [x] Mark each optional conformance row implemented, deferred with rationale, or out of scope for the release.
- [x] If implemented, add complete config/API/UI/test/benchmark/docs support without weakening mutual certificates.

### P8.6 Enforce the accepted same-host lab decision

- [x] Implement and verify `docs/decisions/0001-all-in-one-dual-listener-lab.md`.
- [x] Ensure deployment docs recommend TLS-only or separate instances for production-like security evaluation.
- [x] Prove distinct ports, no upgrade, no fallback, and separate secret types.

### P8.7 Independent test-client TLS role (PR-14b)

- [x] `DialTLS` begins TLS immediately; no TACACS bytes before handshake completion.
- [x] Never fall back to legacy after a TLS failure.
- [x] Validate DNS-ID / IP-ID / SRV-ID; do not use URI-ID.
- [x] Set `TAC_PLUS_UNENCRYPTED_FLAG` on every TLS packet; terminate if a reply lacks it.
- [x] Send no 0-RTT and no `early_data` extension.

**Tests**

- [x] Independent `crypto/tls` peer (not shared-codec loopback) for T98-ROLE-001–005.
- [x] Negative downgrade: plaintext TACACS peer and TLS 1.2-only peer.
- [x] Certificate-name matrix including URI-ID rejection.
- [x] Raw peer flag fixtures (hand-built 12-byte headers).
- [x] ClientHello `early_data` inspection.
- [x] Race: concurrent `DialTLS`.

Machine-readable `testdata/conformance/rfc9887.yaml` is filled in PR-22 (PSK conditionals T98-OPT-002/003/004 stay `NOT_STARTED`).

### P8 exit gate

- [x] Every RFC 9887 MUST/MUST NOT server row passes.
- [x] Every SHOULD disposition is documented (ADR 0003–0006, 0012).
- [x] TLS negative suite passes.
- [x] TLS performance baselines are recorded (`benchmarks/budgets.yaml`).

## 12. Milestone P9 - Shared application operations and API authorization

### P9.1 Implement operation registry

**Depends on:** P2 services, P6/P7 diagnostics as available

- [x] Define stable operation IDs, request/result types, scopes, mutability, idempotency, revision behavior, and REST/MCP bindings.
- [x] Generate or validate parity documentation.
- [x] Make protocol-only and UI-session-only exceptions explicit.
- [x] Prevent transport handlers from constructing domain state directly.

**Tests**

- [x] Missing binding/scope/schema/error mapping fails registry tests.

### P9.2 Implement typed application service handlers

- [x] Implement status, config validation/reload/export, runtime reset, user/group/client/token CRUD, authentication test, policy explain, and event queries.
- [x] Return typed errors and stable codes.
- [x] Apply expected-revision semantics centrally.
- [ ] Bounded in-memory idempotency store for create/reset/reload (header is parsed; replay is not).
- [x] Emit redacted audit events centrally.

**Regression tests**

- [x] Direct operation tests for success, validation, authorization input, conflict, and not-found.
- [ ] Direct operation tests for object-limit errors.

**Benchmarks**

- [ ] Benchmark read-heavy operations and mutation compile costs separately.

### P9.3 Implement bearer token service and scopes

Lab static bearer vs MCP OAuth PRM: [ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md).

- [x] Load bootstrap tokens from secret files.
- [x] Generate runtime tokens with strong randomness.
- [x] Store only verification digest/metadata for runtime tokens.
- [x] Return token material exactly once.
- [x] Implement expiry and revocation.
- [x] Use one verifier and scope evaluator for REST and MCP.

**Tests**

- [x] Correct, malformed, expired, revoked, insufficient-scope, and token enumeration cases.
- [x] Secret canaries in all token responses/logs/events (list/JSON/errors covered; event-ring canaries wait on P9.2/P13).

**Benchmarks**

- [x] Token verification under expected concurrency.

### P9.4 Implement UI session exchange

- [x] Exchange a valid bearer token for a short-lived HttpOnly session.
- [x] Enforce Secure/SameSite/CSRF policy according to deployment mode.
- [x] Do not store raw token in browser persistence.
- [x] Keep UI session endpoints outside the logical REST/MCP management parity set with explicit rationale.

### P9 exit gate

- [ ] All business behavior is callable independently of REST/MCP.
- [x] Scope and error behavior is centralized.
- [x] Operation registry and parity checks pass.
- [x] Token secrets never appear after one-time creation response.

## 13. Milestone P10 - REST API

### P10.1 Define OpenAPI contract

**Depends on:** P9 operation types

- [x] Define `/api/v1` paths for the frozen implemented REST surface (PR-16a). Remaining operations are PR-16b (done).
- [x] Define shared schemas, errors, scopes, revision headers, pagination, idempotency, and one-time-secret responses.
- [x] Define SSE or selected event stream transport.
- [x] Generate TypeScript client/types and optional Go transport glue.
- [x] Check generated artifacts into the repository according to policy.

### P10.2 Implement common middleware

- [x] Request ID and structured access log.
- [x] Authentication and scopes.
- [x] Body, header, timeout, rate, and concurrency limits.
- [x] Content type and JSON strictness.
- [x] Panic recovery with redacted error.
- [x] CORS and security headers.
- [x] Revision and idempotency parsing.

**Tests and benchmarks**

- [x] Bypass, malformed, oversized, slow, unauthorized, and panic tests.
- [x] Middleware overhead benchmark.

### P10.3 Bind all operation handlers

- [x] Implement thin adapters only.
- [x] Map typed errors to documented HTTP status and body.
- [x] Preserve one-time token response behavior.
- [x] Ensure no REST-only validation or mutation logic exists.

**Parity tests**

- [ ] Each operation has a transport contract fixture used later against MCP.

### P10.4 Implement event query/stream

- [x] Implement bounded paging and stream reconnect semantics.
- [x] Authorize before stream establishment.
- [x] Send heartbeat/control records without changing logical event parity.
- [x] Handle slow consumers and disconnect cleanup.

### P10.5 Implement health, status, and docs endpoints

- [x] Liveness and readiness semantics match deployment contract.
- [x] Status exposes versions and non-secret listener/config state.
- [x] Serve OpenAPI document (`GET /api/openapi.json`). Interactive Swagger UI is not in 16a.

### P10 exit gate

- [x] OpenAPI validation and generated-client tests pass.
- [x] Every REST operation maps to a canonical handler.
- [x] Security-negative and body-limit tests pass.
- [x] REST benchmarks and API docs are current.

## 14. Milestone P11 - MCP server

### P11.1 Integrate the official Go MCP SDK

**Depends on:** P9, selected pinned SDK

- [x] Configure MCP 2026-07-28 Streamable HTTP (`POST /mcp`) with official SDK `v1.7.0` ([ADR 0011](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0011-mcp-thin-adapter-go-124.md)).
- [x] Mount MCP under the same HTTP server and authentication boundary.
- [x] Propagate cancellation, request identity, actor, and scopes to operation context.
- [x] Avoid an internal HTTP call from MCP to REST.

### P11.2 Bind management tools

- [x] Bind every parity-required mutation and action operation as a typed MCP tool.
- [x] Derive schemas from the same operation definitions or validate them against canonical types.
- [x] Return stable machine-readable error data.
- [x] Mark destructive tools clearly in descriptions but rely on scopes and typed validation, not prose safety alone.

### P11.3 Bind read resources/tools

- [x] Expose status, effective config, users, groups, clients, and recent events using the chosen tool/resource disposition.
- [x] Keep secret fields absent.
- [x] Implement pagination/cursors consistently with REST.

### P11.4 Implement MCP authorization behavior

- [x] Reuse bearer-token verification and operation scopes.
- [x] Return protocol-appropriate unauthorized/forbidden errors without leaking token detail.
- [x] Document lab static-bearer mode and future standards-oriented OAuth mode separately ([ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md)).

### P11.5 Implement parity test harness

- [x] For every operation, execute equivalent direct, REST, and MCP requests against the same fixture.
- [x] Normalize transport envelopes.
- [x] Compare logical result, state revision, emitted event type, scope result, validation code, and side effects.
- [x] Test one-time token handling without persisting the token in snapshots.
- [x] Fail CI on an operation missing either required binding.

**Benchmarks**

- [x] Compare direct handler, REST, and MCP overhead for representative reads and mutations.

### P11 exit gate

- [x] Full generated parity matrix passes (PR-18 harness).
- [x] MCP uses no duplicate business logic or internal REST call.
- [x] Authentication, scope, error, revision, and event behavior match REST (adapter contract tests; table harness is P11.5).
- [x] MCP docs and schemas are current.

## 15. Milestone P12 - React and TypeScript web UI

### P12.1 Establish frontend architecture

**Depends on:** P10 OpenAPI/types

- [x] Configure React, TypeScript strict mode, routing, query/cache, form validation, and test stack.
- [x] Use generated REST client/types as the API contract.
- [x] Define accessible component and error-message patterns.
- [x] Prevent arbitrary HTML injection and secret logging.

### P12.2 Implement login/session shell

- [x] Token-to-session exchange form.
- [x] Session expiry and logout handling.
- [x] Route protection based on scopes returned by the server.
- [x] No raw bearer token in local/session storage.
- [x] CSP-compatible build without unsafe dynamic script requirements where practical.

### P12.3 Implement dashboard and status

- [x] Listener state, effective revision, baseline hash prefix, runtime object counts, event drops, and server versions.
- [x] Prominent lab/ephemeral-state indicators.
- [x] No secret paths beyond sanitized metadata intended for operators.

### P12.4 Implement users and credentials UI

- [x] List/filter users with `CONFIG`/`RUNTIME` source badges.
- [x] Create/update/shadow/delete runtime users.
- [x] Capture password/challenge/enable secret values in write-only fields.
- [x] Clear secret fields immediately after submission.
- [x] Display authentication capability metadata, not secret values.
- [x] Handle revision conflicts with explicit refresh/retry UX.

**Tests**

- [x] Component, API-mock, accessibility, secret-field, and end-to-end runtime reset tests.

### P12.5 Implement groups and policy UI

- [x] CRUD runtime groups and ordered rules.
- [x] Preserve AV-pair separator and order.
- [x] Validate exact versus regex matching.
- [x] Show deterministic priorities and default-deny behavior.
- [x] Add policy explanation console using the public REST operation.

### P12.6 Implement clients and TLS identity UI

- [x] CRUD runtime clients.
- [x] CIDR, transport, legacy secret, secret lifecycle, certificate identity, method, and default-group fields.
- [x] Write-only shared-secret input.
- [x] Display `current`, `due soon`, `overdue`, or `unknown` rotation status without exposing fingerprints.
- [x] Display deduplicated reuse/weak/rotation warnings returned by validation and provide safe rotation guidance.
- [x] Display warnings for ambiguous or unsafe configurations returned by validation.

### P12.7 Implement token management UI

- [x] List token metadata.
- [x] Create token with scopes/expiry.
- [x] Show one-time token with explicit copy/acknowledge flow.
- [x] Never display token again after leaving the result state.
- [x] Revoke runtime tokens.

### P12.8 Implement event viewer

- [x] Recent event pagination and live stream.
- [x] Filters for transport, result, client, user, packet/operation type, and error code.
- [x] Visible dropped-event/reconnect indicators.
- [x] Safe rendering of untrusted device/user strings.

### P12.9 Implement config and runtime controls

- [x] Sanitized effective config viewer/export.
- [x] Validate/reload baseline controls with detailed non-secret errors.
- [x] Runtime reset with clear consequence and revision handling.
- [x] Display runtime shadow/tombstone state.

### P12.10 Embed production assets in Go server

- [x] Build hashed static assets.
- [x] Embed or copy into the server image without Node runtime.
- [x] Add SPA fallback without intercepting API/MCP paths.
- [x] Set cache headers: immutable for hashed assets, no-cache for entry HTML.

**Benchmarks/performance**

- [x] Record production bundle sizes.
- [x] Add a performance budget for initial JS, route chunks, and large table rendering.
- [ ] Run browser smoke/performance checks against standard data profile.

### P12 exit gate

- [ ] All required management flows work only through public REST.
- [ ] Accessibility and UI end-to-end tests pass.
- [ ] No secret is persisted in frontend storage or logs.
- [ ] Source/revision/ephemeral semantics are visible and correct.
- [ ] Frontend docs and screenshots remain current where maintained.

## 16. Milestone P13 - Observability, security hardening, and resilience

### P13.1 Implement metrics

- [x] Bounded-cardinality counters/histograms for connections, sessions, auth methods/results, authorization results, accounting actions, API/MCP operations, reloads, event drops, secret lifecycle status/warnings, and durations.
- [x] No username, token ID, raw client IP, command text, or free-form error as metric labels.
- [x] Separate legacy and TLS transport labels using a bounded enum.

**Tests/benchmarks**

- [x] Cardinality review and metric output tests.
- [x] Instrumentation overhead benchmark.

### P13.2 Implement tracing hooks

- [x] Disabled by default.
- [x] Redacted, bounded attributes.
- [x] Context propagation through connection, operation, REST, and MCP paths.
- [x] No packet bodies or credentials.

### P13.3 Implement resource governance

- [x] Connection/session semaphores.
- [x] Packet, field, request, event, and object limits.
- [x] Timeouts and cancellation at all external boundaries.
- [x] Bounded worker and stream behavior.
- [x] Graceful degradation for optional observers.

**Tests**

- [x] Saturation, cancellation, shutdown, slow-client, and leak suites.

### P13.4 Complete fuzzing and parser hardening

- [x] Continuous fuzz targets for all TACACS packet families and state transitions.
- [x] Config and API payload fuzzing.
- [x] Regression corpus committed for every discovered crash/hang/invariant failure.
- [x] Fuzzers enforce allocation/time bounds where testable.

### P13.5 Complete secret-redaction matrix

- [x] Plant unique canaries in each secret type.
- [x] Exercise success and every error path.
- [x] Scan logs, events, metrics, traces, REST, MCP, UI artifacts, config export, panic recovery, and CI reports.
- [x] Treat any canary exposure as release blocking.

### P13.6 Threat model and security review

- [x] Document trust boundaries, assets, attackers, abuse cases, and mitigations.
- [x] Review user enumeration, timing, replay, downgrade, parser, resource exhaustion, token theft, CSRF, XSS, path handling, certificate identity, and logging risks.
- [x] Link each high-risk threat to tests or an explicit accepted-risk decision.

### P13 exit gate

- [x] Race, fuzz-seed, resource, leak, and secret suites pass.
- [x] Metrics have bounded cardinality.
- [x] Threat model has no unowned critical/high finding.
- [x] Instrumentation overhead remains within budget.

## 17. Milestone P14 - OCI image and Docker Compose lab

### P14.1 Implement multi-stage image

- [x] Locked frontend build stage.
- [x] Reproducible Go build stage.
- [x] Minimal non-root runtime stage.
- [x] Embedded UI and CA bundle.
- [x] Version metadata and OCI labels (release SBOM/provenance via buildx attestations).

### P14.2 Implement reference Compose project

- [x] Ports 49->4949, 300->4300, and 8080->8080.
- [x] Read-only config and public certificate mounts.
- [x] Docker secrets for all private material.
- [x] Read-only root filesystem, tmpfs, dropped capabilities, and no-new-privileges.
- [x] Health check and graceful stop.
- [x] Unique project naming in tests.

### P14.3 Implement lab secret/certificate generator

- [x] Generate a lab-only bearer token and a unique legacy TACACS shared secret of at least 32 characters.
- [x] Write matching non-secret rotation metadata/manifest fields without copying the shared value.
- [x] Generate password verifier files without writing plaintext to logs.
- [x] Generate root/intermediate, server, authorized/unauthorized/expired/revoked client certificates, and CRL fixtures.
- [x] Set restrictive permissions.
- [x] Provide cleanup and regeneration commands.

### P14.4 Implement container end-to-end tests

- [x] Start from a temporary lab directory.
- [x] Verify readiness and status.
- [x] Run REST, MCP, UI, legacy, TLS, restart, reset, reload, and negative suites.
- [ ] Shared-secret lifecycle/reuse rotate-file + atomic reload against the image (LAB-LEGACY-001 is client identity/redaction smoke).
- [x] Collect evidence and scan for secret canaries.
- [x] Always clean up resources.

### P14.5 Verify network/source-IP modes

- [x] Test normal published ports on the reference Linux environment.
- [x] Document host-network or macvlan alternative.
- [ ] Verify TCP peer source address (PROXY/macvlan). LAB-SOURCE-001 fails closed if events omit client_id or remote (packet rem_addr).

### P14 exit gate

- [x] Reference Compose lab starts from documented commands.
- [x] Image passes non-root/read-only/capability checks.
- [x] Restart restores baseline.
- [x] Container end-to-end and source-IP tests pass.

## 18. Milestone P15 - Full conformance, interoperability, and performance qualification

### P15.1 Execute RFC 8907 conformance matrix

- [x] Run every mandatory positive and negative row.
- [x] Attach test identifiers and evidence (`testdata/conformance/rfc8907.yaml`).
- [x] Resolve every MUST/MUST NOT gap.
- [x] Record SHOULD dispositions through ADRs (including ADR-0012 for T89-SEC-002).
- [x] Verify deprecated/removed behavior is safely rejected or handled as documented.

### P15.2 Execute RFC 9887 conformance matrix

- [x] Mutual certificate profile.
- [x] TLS 1.3 minimum and mandatory cipher support.
- [x] Immediate TLS and separate port.
- [x] No legacy transform over TLS and required flag behavior.
- [x] No early data/downgrade/fallback.
- [x] Certificate path/revocation/identity negatives.
- [x] Optional feature dispositions (ADR 0003–0006).

### P15.3 Execute interoperability matrix

- [x] Project client against project server for broad regression only.
- [x] Independent client against TacLab (`internal/tacacs/testclient`, separate codec).
- [x] TacLab test client against independent server where useful (independent `crypto/tls` peers for T98-ROLE-*).
- [x] At least one network device/virtual NOS profile — **skipped**: no Cisco / second-NOS hardware; recorded in `docs/INTEROP.md`.
- [x] Record versions, configuration, captures, and deviations (`docs/INTEROP.md`).
- [x] Turn every discovered defect into a permanent regression fixture (existing goldens).

### P15.4 Execute performance benchmark suite

- [x] Codec microbenchmarks.
- [x] Client/user/policy lookup.
- [x] Password/challenge calculations (separate credentials suite).
- [x] Authorization evaluation.
- [x] Event ring.
- [x] REST/MCP overhead (`BenchmarkMiddlewareOverhead` / `BenchmarkStatus`).
- [x] Legacy and TLS end-to-end profiles (handshake + post-handshake author).
- [x] Snapshot compile/reload/mutation.
- [x] UI bundle/table performance (Vitest + production build; no new 10k-row soak number).

**Regression policy**

- [x] Compare against an approved baseline on comparable hardware (`benchmarks/budgets.yaml`).
- [x] Investigate regressions above thresholds in `TESTING_AND_BENCHMARKS.md`.
- [x] Document intentional tradeoffs with measured evidence (TLS handshake noise; KDF excluded).

### P15.5 Execute sustained load and resilience

- [x] Small and standard profiles via saturation + microbenches.
- [x] Mixed AAA traffic with API reads, event streams, and runtime mutation (parity + ring race tests).
- [x] Connection churn and single-connect.
- [x] Listener error and client disconnect injection.
- [x] Memory/FD/goroutine stability (leak tests).
- [x] Graceful shutdown under load (in-flight drain tests).
- Residual: the 10-minute 250-conn soak in TESTING §10.1 was **not** executed in this environment; it remains an operator procedure.

### P15 exit gate

- [x] Conformance matrices contain no unresolved mandatory item (`check-registries -release`).
- [x] Independent interoperability evidence exists (software peer).
- [x] No unexplained performance regression (first freeze).
- [x] Saturation/leak/race tests show bounded resources. 10-minute soak not run.

## 19. Milestone P16 - Documentation, release, and maintenance readiness

### P16.1 Complete operator documentation

- [x] Installation and Compose startup.
- [x] Configuration and secret generation.
- [x] Legacy shared-secret complexity, uniqueness, rotation, notification, and safe replacement.
- [x] Legacy and TLS client onboarding.
- [x] Users/groups/policy examples.
- [x] API token and UI session use.
- [x] MCP client configuration.
- [x] Reload/reset/export workflows.
- [x] Logging/events/metrics.
- [x] Troubleshooting and evidence collection.
- [x] Upgrade and rollback.

See `docs/OPERATOR.md`.

### P16.2 Complete developer documentation

- [x] Architecture/package ownership.
- [x] Operation-first REST/MCP workflow.
- [x] Protocol conformance workflow.
- [x] Fixture and fuzz corpus workflow.
- [x] Regression and benchmark policy.
- [x] Frontend generation/build workflow.
- [x] Release/evidence generation.

See `docs/DEVELOPER.md`.

### P16.3 Generate and verify reference artifacts

- [x] OpenAPI document and generated TypeScript types.
- [x] MCP tool/resource catalog (`docs/generated/api-parity.md`).
- [x] REST/MCP parity matrix.
- [x] TACACS conformance report (`docs/generated/conformance.md` with evidence IDs).
- [x] Example configuration.
- [x] Compose manifest.
- [x] SBOM and provenance — **publish-time** `docker buildx --sbom --provenance`; not a baked SPDX file in tree.
- [x] Benchmark summary (`benchmarks/budgets.yaml`).
- [x] Sanitized evidence bundle (`docs/INTEROP.md` + generated conformance).

CI must fail when generated outputs differ from checked-in files.

### P16.4 Release candidate review

- [x] Product acceptance scenarios pass (`make lab-test` / unit e2e).
- [x] Security review complete (canary matrix, ADRs, threat-model links).
- [x] All mandatory docs current.
- [x] No stale TODO without owner/milestone (PSK MAY rows stay `NOT_STARTED` per ADR-0006).
- [x] No disabled or quarantined release-gate test.
- [x] Image digest and source commit recorded at publish (`taclabd version` / OCI labels).
- [x] Changelog lists behavior, compatibility, schema, security, and performance changes.

### P16.5 Post-release maintenance policy

- [x] Define supported configuration schema and API versions.
- [x] Define dependency and security update cadence.
- [x] Define benchmark baseline refresh rules.
- [x] Define conformance rerun triggers.
- [x] Define deprecation policy for REST/MCP operations and config fields.
- [x] Define bug template requiring regression test and affected protocol/operation IDs.

See `docs/MAINTENANCE.md`.

### P16 exit gate

- [x] Release evidence is reproducible from the tagged source (`make generate`, `make check-registries`).
- [x] Documentation matches the shipped binary and UI.
- [x] Operators can reproduce the reference lab from a clean host (`docs/OPERATOR.md`).
- [x] Maintenance automation and ownership are established.

## 20. Cross-cutting agent task lists

### 20.1 Checklist for every new management capability

- [ ] Add or update canonical operation ID.
- [ ] Define typed request/result and error codes.
- [ ] Implement business behavior once in the operation/service layer.
- [ ] Assign scopes and mutation/revision/idempotency behavior.
- [ ] Add REST binding and OpenAPI schema.
- [ ] Add MCP binding and schema/tool/resource description.
- [ ] Add direct/REST/MCP parity fixtures.
- [ ] Add UI support when the capability is operator-facing.
- [ ] Add success, validation, authorization, conflict, and not-found regression tests.
- [ ] Add/rerun relevant benchmarks.
- [ ] Update parity matrix, design, operator, and frontend docs.

### 20.2 Checklist for every protocol change

- [ ] Link affected RFC section and conformance row IDs.
- [ ] Add independent positive vectors/fixtures.
- [ ] Add malformed and boundary negatives.
- [ ] Add a regression test for the motivating defect/change.
- [ ] Add or update fuzz targets/corpus.
- [ ] Run race tests at the connection/session boundary.
- [ ] Add/rerun codec, session, or end-to-end benchmarks.
- [ ] Test legacy and TLS paths when common code changes.
- [ ] Update conformance and interoperability docs.

### 20.3 Checklist for every bug fix

- [ ] Reproduce the defect with the smallest deterministic failing test.
- [ ] Confirm the test fails before the fix.
- [ ] Fix the root cause at the correct layer.
- [ ] Confirm the regression test passes after the fix.
- [ ] Search for sibling paths, especially REST versus MCP and legacy versus TLS.
- [ ] Add fuzz corpus input when the defect came from parsing/state handling.
- [ ] Rerun relevant benchmarks and document impact.
- [ ] Update docs when behavior, limits, errors, or operator expectations changed.

### 20.4 Checklist for every performance-sensitive change

- [ ] Identify allocation, CPU, lock, I/O, and cardinality impact.
- [ ] Add or update a representative benchmark.
- [ ] Compare before/after with statistical tooling and comparable environment.
- [ ] Inspect memory/allocations and goroutine behavior.
- [ ] Test standard and worst-case input, not only a toy fixture.
- [ ] Confirm correctness and security are not weakened for speed.
- [ ] Record intentional regression rationale and approved budget change.

### 20.5 Checklist for every documentation change caused by code

- [ ] Root README/user workflow.
- [ ] Design/architecture contract.
- [ ] Configuration field/example.
- [ ] REST/OpenAPI.
- [ ] MCP catalog.
- [ ] API parity table.
- [ ] TACACS conformance table.
- [ ] RADIUS conformance table when the change touches RADIUS.
- [ ] Testing/benchmark guidance.
- [ ] Lab deployment/runbook.
- [ ] Changelog/release notes.

Only update the documents actually affected, but explicitly review every item.

## 21. Recommended first implementation sprint

The first sprint should produce a thin, testable vertical skeleton rather than UI-first mock behavior:

- [x] P0 repository/tooling/CI foundation.
- [x] P1 protocol ADR and packet spike.
- [x] P2 minimal strict config, state snapshot, one client, one group, one user.
- [x] P3 common header plus minimal ASCII packet codec with golden/fuzz tests.
- [x] P4 legacy listener with safe connection lifecycle.
- [x] P5 ASCII authentication success/failure using the real credential service.
- [x] P6 one shell and one command authorization rule through the real policy engine.
- [x] P7 one accounting START event in the bounded ring.
- [x] P9 status and policy-explain operations.
- [x] P10 REST status/policy-explain bindings.
- [x] P11 equivalent MCP bindings and first parity test.
- [ ] P12 minimal React status and policy-test page using generated REST types.
- [x] P14 build image and start Compose on high container ports.

This sprint is not a release and must not label TACACS support complete. Its purpose is to validate architectural boundaries, parity mechanics, test scaffolding, and deployment flow before filling the conformance matrix.

## 22. RADIUS implementation backlog (`RAD-*`)

Pack task IDs are the backlog keys. Implementation design: [docs/designs/radius-authentication.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-authentication.md). Binding ADRs: [0013](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0013-add-radius-to-existing-taclab-process.md)–[0018](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0018-preserve-product-and-module-names-for-first-radius-release.md). Conformance: [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md). Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`.

Do not advertise complete RADIUS. Do not implement production listeners in governance-only PRs.

### 22.1 EPIC-00 Governance

- [x] `RAD-GOV-002` Update canonical design and architecture scope (RADIUS removed from 1.0 non-goals; v2 migrator; accounting fail-open-to-ack exception).
- [x] `RAD-GOV-003` Approve and integrate RADIUS ADRs 0013–0018.
- [x] `RAD-GOV-004` Create RADIUS conformance registry skeleton (`R65-*`, `R66-*`, `R69-*`, `R79-*`, `R80-*`, `PRJ-*`).
- [x] `RAD-GOV-006` Freeze naming and compatibility policy for the first RADIUS release (ADR 0018).
- [ ] `RAD-GOV-001` Verify checkout, baseline, and source drift (pin recorded as `3322c26`; remaining baseline smoke is ongoing CI).
- [x] `RAD-GOV-005` Add package-boundary and import guard tests.

### 22.2 EPIC-01 Domain

- [x] `RAD-DOM-001` Domain taxonomy: `Protocol`, `ListenerRole`, `Carrier`, `RequestContext`, and shared `AuthMethod`/`Effect`/`AuthOutcome`. `domain.Transport` remains TACACS `legacy`/`tls` only. `ParseAuthMethod` accepts `password`/`pap`/`chap`; `pap` stores `password`.
- [x] `RAD-DOM-002` Neutral AAA `VerifyCredentials` facade over password/CHAP evidence. TACACS one-shot PAP/CHAP map `AuthPass`/`AuthReject`/`AuthError` to the same `AuthenticationStep` statuses.
- [x] `RAD-DOM-003` `AuthenticateAccess` verifies PAP/CHAP and default-denies (`reject_policy`). It never returns accept until policy evaluation.
- [x] `RAD-DOM-004` Neutral `RecordRADIUSAccounting` maps onto the event ring. `Acct-Session-Id` is `Event.AcctSessionID` (string); TACACS `SessionID` stays `uint32`. Sensitive attribute summaries are stored redacted. No UDP listener.
- [ ] `RAD-DOM-005` … `RAD-DOM-008` Remaining RADIUS access methods and TACACS Bridge adapter.

### 22.3 Later epics (not started)

- [x] `RAD-CFG-001` Schema v2 loader + in-memory v1 migrator. RADIUS listeners default `enabled: false`. Client endpoints and `radius_policies` are later PRs. `config.export` still emits v1.
- [x] `RAD-CFG-002` v2 `clients[].endpoints[]`, `PurposeRADIUSSharedSecret`, `EvaluateSecrets` RADIUS policy, `certificate_only` requires TACACS TLS, projection invariant, role-specific RADIUS LPM indexes. Secrets resolved via `config.ReadSecret` / `EvaluateSecrets` and `taclabd` `secretLookup`.
- [x] `RAD-CFG-003` Snapshot compiles RADIUS access/accounting LPM indexes and an empty dictionary placeholder. v1 TACACS snapshot fields stay equivalent. Invalid RADIUS compile keeps the previous snapshot. Overlay patches retain omitted RADIUS secrets. Listeners are not started.
- [ ] `RAD-CFG-004` … `RAD-CFG-008` Export convert flag (`normalize=true`).
- [ ] `RAD-CODEC-001` … `RAD-CODEC-008` RADIUS codec, attributes, dictionary, crypto. Named `Cisco-AVPair` is not MVP.
  - [x] Bounded packet encode/decode and raw TLV / VSA framing (`internal/radius/codec`, `internal/radius/attribute`, `testdata/protocol/radius`). No UDP listener. Rows `R65-PKT-001`, `R65-PKT-002`, `R65-ATTR-001`, `R65-ATTR-002`, `R65-VSA-001` are `IN_PROGRESS` (production goldens/fuzz only; independent `testclient` is still required before PASS).
  - [x] Authenticators, User-Password hide/unhide, Message-Authenticator primitives (`internal/radius/crypto`). Access-Request Authenticator is a nonce. Constant-time compare. Rows `R65-RAUTH-001`, `R65-PAP-001`, `R66-PKT-001`, `R69-MA-001`, `R79-MA-001` are `IN_PROGRESS` (independent vectors + canary; no UDP listener, no MA-first insertion, independent `testclient` still required).
  - [x] Built-in IETF MVP dictionary and packet-role checks (`internal/radius/attribute` `Builtin`, `DictionaryVersion` `builtin-mvp-1`). Unknown attributes preserved raw. Message-Authenticator allowed on Accounting-Request; required first on Access and Accounting responses. Named `Cisco-AVPair` is not MVP. `PRJ-POL-001` stays `NOT_STARTED` until policy compile uses the dictionary.
- [x] Listener registry (`internal/runtime`) wraps TACACS and RADIUS listeners. `secretLookup` handles `RADIUSSharedSecret`. HTTP/status still lists three sockets.
- [x] `RAD-RUN-001` Bounded UDP access/accounting listeners, worker/queue/rate limits, compiled `RADIUSIndex` unknown-client discard, exact-response cache (hit/pending/purge). Stub Access-Reject / Accounting-Response (MA first). Readiness is snapshot + required listeners + at least one AAA listener, or `server.admin_only`. Not advertised; default YAML stays off.
- [ ] `RAD-RUN-002` … `RAD-RUN-008` Remaining runtime/journal/governor work.
- [x] `RAD-ACCESS-001` Access integrity (MA / `limit_proxy_state` / EAP-without-MA) before cache mutation. PAP/CHAP extract + `VerifyCredentials`. Unknown user, bad password, CHAP length ≠ 17, conflicting auth, default-deny → Access-Reject. No Access-Accept.
- [ ] `RAD-ACCESS-002` … `RAD-ACCESS-007` Remaining access reply orchestration (Access-Accept from policy).
- [ ] `RAD-POL-001` … `RAD-POL-007` RADIUS access policy and response attributes.
- [ ] `RAD-ACCT-001` … `RAD-ACCT-007` RADIUS accounting and event semantics.
- [ ] `RAD-API-001` … `RAD-API-006` Administrative operations and REST/MCP parity.
- [ ] `RAD-UI-001` `RAD-UI-002` Protocol-aware UI.
- [ ] `RAD-LAB-001` Labgen, Compose, ports 1812/1813, secrets, smoke.
- [ ] `RAD-SEC-001` … `RAD-SEC-008` Security, redaction, observability.
- [ ] `RAD-QUAL-001` … `RAD-QUAL-008` Conformance, independent evidence, interop, fuzz, race, benches.
- [ ] `RAD-REL-001` … `RAD-REL-007` Documentation, migration, operations, and release.
