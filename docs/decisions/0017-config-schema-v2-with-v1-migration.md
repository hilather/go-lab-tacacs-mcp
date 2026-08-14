# ADR 0017: Configuration Schema Version 2 with Deterministic Version 1 Migration

Status: Accepted  
Date: 2026-08-14  
Decision owners: TacLab maintainers  
Related tasks: RAD-CFG-001, RAD-CFG-002, RAD-CFG-003, RAD-CFG-007, RAD-REL-002  
Related conformance rows: PRJ-CFG-001  
Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`

## Context

Current schema version 1 is strict and TACACS-shaped: fixed TACACS listeners, transport values `legacy`/`tls`, a TACACS legacy secret block, TACACS authentication-method configuration, and TACACS accounting flags. The canonical design explicitly requires a deterministic migrator and golden tests for future versions.

RADIUS needs protocol/transport/role endpoint profiles, separate access/accounting listeners, RADIUS secret and Message-Authenticator policy, typed response attributes, and role-specific matching.

## Decision

1. New multi-protocol/RADIUS configurations use schema version 2.
2. The loader continues to accept strict version 1 and deterministically migrates it **in memory** to the normalized v2 model. Source files are never rewritten automatically.
3. Version-specific raw syntax structs stay private. Mixed v1/v2 syntax is rejected.
4. Migration preserves all existing TACACS behavior, IDs, matching, priorities, secret references, policy, metadata, and defaults.
5. Golden tests compare v1 and equivalent v2 effective TACACS snapshots.
6. `config.export` **never** emits v2 YAML for a v1 source without an explicit convert flag. v1 sources export as v1. The flag is the existing `normalize=true` on export; default remains false. Operators must pass that flag to get v2 YAML. Do not auto-upgrade or silently reshape a v1 export.

v2 listener YAML is named nested blocks (`listeners.tacacs.legacy`, `listeners.radius.access`), not a listener list. v2 client YAML uses shared `match.source_cidrs` plus `endpoints[]`. Internal `config.Client` keeps existing TACACS fields as a compatibility projection.

## Alternatives considered

### Additive v1 extension with RADIUS fields

Rejected. It makes TACACS leakage permanent and contradicts the canonical migrator contract.

### Listener list in v2 YAML

Rejected for the first release. Current `rawListeners` / `serve.go` / `status.go` are named. Named nested blocks are the smaller change.

### Auto-rewrite source files to v2 on load or export

Rejected. User decision 2026-08-14: v1 sources export as v1 unless `normalize=true`. Disk files are never rewritten by the server.

## Consequences

### Positive

- The public schema reflects the target architecture instead of compatibility debt.
- Existing operators can upgrade binaries without immediately editing v1 files.
- The migration path is explicit, testable, and consistent with the current canonical contract.

### Negative

- Loader, export, validation, docs, UI, and generators must understand source/effective schema versions.
- Old binaries cannot parse v2. Rollback is “keep the v1 file.”

## Compatibility impact

Existing `schema_version: 1` files load unchanged and compile to the same TACACS effective state. RADIUS configuration requires `schema_version: 2`. This ADR does not change production parse behavior in the same commit; the migrator lands in a later PR.

## Migration

- Binary upgrade only for v1 deployments. RADIUS listeners stay disabled until explicitly enabled in v2.
- Rollback: keep the v1 file. Do not auto-convert files on disk.
- Overlay is discarded on restart (unchanged).

## Test impact

- All current v1 fixtures must keep passing.
- v2 TACACS-equivalent goldens must match v1 effective TACACS snapshots.
- Mixed v1/v2 keys fail with a stable path.
- Export without `normalize=true` from a v1 source is v1 YAML.

## Documentation impact

CANONICAL_DESIGN migration section records v1→v2 in-memory migration and the export flag. Operator configuration reference updates when the loader lands.

## Revisit conditions

- A later schema version 3 is required.
- Export needs a dedicated convert operation distinct from `normalize`.
