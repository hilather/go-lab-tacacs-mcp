# ADR 0013: Add RADIUS to the Existing TacLab Process and Repository

Status: Accepted  
Date: 2026-08-14  
Decision owners: TacLab maintainers  
Related tasks: RAD-GOV-002, RAD-GOV-003, RAD-GOV-006  
Related conformance rows: PRJ-TAC-001, PRJ-CFG-001, PRJ-PAR-001  
Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`

## Context

TacLab is a single Go process with multiple listeners, one immutable effective-state snapshot, one runtime overlay, one AAA/policy/event core, and one canonical administrative operation registry. A separate RADIUS repository would duplicate identities, clients, secrets, policy provenance, state compilation, REST/MCP parity, UI, observability, packaging, and release gates.

RADIUS still differs materially from TACACS in transport, packet model, attributes, authorization expression, accounting, retransmission, and state. Those differences must not be papered over by embedding RADIUS inside `internal/tacacs` or by translating RADIUS through TACACS statuses.

This ADR is adopted from the architecture pack at source pin `3322c26` and refined by [docs/designs/radius-authentication.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-authentication.md).

## Decision

Implement RADIUS in the existing repository and `taclabd` process.

1. Add RADIUS packages as peers of TACACS packages under `internal/radius`.
2. Reuse shared application/state capabilities through protocol-neutral contracts (ADR 0014).
3. Do not embed RADIUS inside `internal/tacacs`.
4. Do not proxy RADIUS through TACACS semantics (`BeginAuthentication`, `domain.AVPairs`, TACACS accounting flags).
5. Do not introduce a second daemon, second snapshot manager, or second operation registry.

Product, module, binary, and image names stay unchanged for the first RADIUS release (ADR 0018).

## Alternatives considered

### New `go-lab-radius-mcp` repository

Rejected. It duplicates the product core and will drift. Two revisions cannot stay atomic.

### RADIUS-to-TACACS translation layer

Rejected. RADIUS response attributes, UDP retransmissions, and accounting semantics are not TACACS statuses or sessions.

### Sidecar process sharing YAML

Rejected. It creates two snapshots and non-atomic runtime mutations.

## Consequences

### Positive

- One lab appliance and one source of truth.
- No duplicated admin/UI/policy/state stack.
- Cross-protocol scenarios use the same identities and revisioned state.
- Existing engineering and release gates apply.

### Negative

- Shared-domain TACACS leakage must be removed carefully.
- Composition root, config, status, metrics, and naming become multi-protocol.
- Regression testing must protect both legacy and TLS TACACS throughout the migration.

## Compatibility impact

Existing TACACS listeners, v1 configuration, REST/MCP operations, and the 1.0 TACACS conformance gate remain required. RADIUS listeners are not enabled by this ADR. No production listener behavior changes here.

## Migration

None for operators. Implementation lands incrementally. Schema version 2 is ADR 0017.

## Test impact

- Existing TACACS conformance (`T89-*`, `T98-*`) remains a merge gate on every shared-package change.
- Import-boundary tests (RAD-GOV-005) forbid `tacacs` ↔ `radius` and adapter-to-adapter imports.
- RADIUS rows start `NOT_STARTED` and must not be marked `PASS` without evidence.

## Documentation impact

- [docs/CANONICAL_DESIGN.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md) removes RADIUS from 1.0 non-goals and states the multi-protocol scope.
- [docs/ARCHITECTURE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md) records the peer-package target.
- [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) is the human RADIUS contract.

## Revisit conditions

- Runtime state becomes replicated or durable.
- Multiple service replicas are supported.
- A production deployment profile requires process isolation between protocols.
