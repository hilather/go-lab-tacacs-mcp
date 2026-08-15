# ADR 0018: Preserve TacLab Product, Module, Repository, and Binary Names Initially

Status: Accepted  
Date: 2026-08-14  
Decision owners: TacLab maintainers  
Related tasks: RAD-GOV-006, RAD-REL-005  
Related conformance rows: PRJ-PAR-001  
Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`

## Context

The repository, Go module, binary, image, documentation, and established user workflows are TACACS-named. Renaming them while adding a new protocol would mix architectural change with broad compatibility and release risk.

## Decision

Keep the following names for the first RADIUS release:

| Surface | Name |
|---|---|
| Product | TacLab |
| Repository | `go-lab-tacacs-mcp` |
| Go module | `github.com/hilather/go-lab-tacacs-mcp` |
| Binary | `taclabd` |
| Image | `ghcr.io/hilather/go-lab-tacacs-mcp` |

Describe the product as a TACACS+ and RADIUS AAA lab appliance. Use additive protocol-aware status/API fields and retain existing TACACS fields for compatibility.

Do not call RADIUS a TACACS mode. Do not set `system.build.get` RADIUS `conformance_status` to `pass` and do not market “complete RADIUS” until MVP conformance rows are evidenced.

Evaluate a broader rename only after the RADIUS release has interoperability evidence and a separate migration ADR covers module/import paths, images, commands, configuration, links, and deprecation periods.

## Alternatives considered

### Rename the module, binary, and image in the first RADIUS PR

Rejected. It mixes protocol work with a compatibility migration and breaks existing Compose, CI, and operator scripts.

### Introduce a second binary (`radiusd`) in the same repo

Rejected. Conflicts with ADR 0013 (one process).

## Consequences

### Positive

- Implementation stays focused on protocol correctness and shared architecture.
- Existing clone, import, image pull, and `taclabd` workflows keep working.

### Negative

- Naming is temporarily narrower than capability.
- Documentation must be explicit to avoid implying RADIUS is a TACACS mode.

## Compatibility impact

No rename. Additive fields only. Existing TACACS status/build JSON remains valid.

## Migration

None now. A later rename ADR must include a deprecation period and dual-name documentation.

## Test impact

- Status/build contract tests must keep current TACACS fields.
- Capability advertisement tests must refuse a RADIUS `pass` badge while rows are `NOT_STARTED`.

## Documentation impact

AGENTS.md, CANONICAL_DESIGN, and operator docs describe TacLab as a TACACS+ and RADIUS lab without claiming RADIUS completeness.

## Revisit conditions

- RADIUS interop evidence exists and operators request a protocol-neutral name.
- A dedicated rename ADR covers module path, images, commands, and links.
