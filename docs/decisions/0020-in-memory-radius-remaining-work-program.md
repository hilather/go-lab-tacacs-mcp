# ADR 0020: In-Memory RADIUS Remaining-Work Program Charter

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-009, RAD-GOV-001  
Related conformance rows: PRJ-ACCT-002, PRJ-UL-001  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

TacLab `v1.2.0` ships a bounded RADIUS/UDP lab profile. Overlay, retransmission cache, semantic journal, and event ring are process memory. Restart and `runtime.reset` restore the YAML baseline.

Operators asked for the remaining RADIUS backlog (Access-Challenge, lab EAP, RADIUS MS-CHAP, CoA/Disconnect, RadSec, operator dictionaries, named `Cisco-AVPair`, user/group RADIUS rules) **without** changing the storage model. Persistent accounting (`RAD-EXT-009`) would reopen durability, retention, privacy, backpressure, and replica questions that the lab appliance does not take on.

`system.build.get` RADIUS `conformance_status` is hard-coded `partial`. AGENTS.md 2.7 forbids a complete-RADIUS badge while in-scope rows lack evidence or remain residual.

## Decision

1. **Storage stays process memory.** Overlay, Challenge store, CoA session index, retransmission cache, journal, and event ring are wiped on restart and `runtime.reset`. Do not implement persistent accounting in this program.
2. **`RAD-EXT-009` is cancelled for this program.** A later ADR may add an opt-in disk sink. This DAG must not grow one.
3. **Stay on schema v2.** New keys are additive. v1 files stay valid and TACACS-equivalent. Source files are never rewritten. `config.export` `normalize=true` behavior is unchanged ([ADR 0017](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0017-config-schema-v2-with-v1-migration.md)).
4. **`system.build.get` RADIUS `conformance_status` stays `partial`** for this entire program, even after every in-scope extension row is `PASS` or an accepted `DEFERRED_MAY`. Do not ship a complete-RADIUS badge.
5. **ADRs 0020–0029 land as documentation before the matching implementation PRs.** Implementation PRs cite the ADR in conformance `evidence:`. This ADR is the program charter; ADRs 0021–0029 bind the individual extensions.
6. **Leftover unchecked MVP ranges** in [docs/TASKS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TASKS.md) §22.3 are closed or superseded into `RAD-EXT-*`. They are not a second implementation backlog.
7. New admin capabilities remain `PARITY_REQUIRED`. Secrets never appear in logs, events, traces, REST/MCP, or UI.

## Alternatives considered

### Implement persistent accounting “just in case”

Rejected. Operator decision. Memory ring/journal only.

### Flip `conformance_status` to `pass` after the extension DAG

Rejected. Persistent accounting is cancelled; DTLS/1.1, tunneled EAP, and proxying stay deferred. A later product ADR would be required to advertise completeness despite those residuals.

### Schema v3 for new listeners and dictionaries

Rejected. Named nested v2 blocks extend cleanly. v1 migrator stays as-is.

## Consequences

### Positive

- Remaining RADIUS work has a single in-memory contract.
- Operators keep restart / `runtime.reset` as the restore path.
- Completeness advertising stays honest.

### Negative

- Accounting, Challenge state, and CoA session rows do not survive restart.
- Multi-replica / HA session sharing stays out.

## Compatibility impact

No production behavior change. Existing v1/v2 YAML, UDP listeners, and REST/MCP operations stay as shipped. New listeners remain `enabled: false` when they land in later PRs.

## Migration

None. Operators who later need disk accounting wait for a new ADR. Rollback of this documentation change has no runtime effect.

## Test impact

- Existing tests that lock RADIUS `conformance_status` to `partial` stay merge gates.
- Implementation PRs must wipe Challenge store and session index on `runtime.reset` / process exit.
- Do not add a disk accounting sink or a completeness badge in this program.

## Documentation impact

This ADR is the charter for [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md). [docs/TASKS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TASKS.md) §22.3–22.4 and [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) §8 record leftover disposition and still-deferred rows until implementation PRs attach evidence.

## Revisit conditions

- An operator ADR accepts an opt-in, bounded disk accounting sink.
- A product ADR is willing to advertise RADIUS completeness despite cancelled persist and the deferred residuals (DTLS/1.1, tunneled EAP, proxying).
