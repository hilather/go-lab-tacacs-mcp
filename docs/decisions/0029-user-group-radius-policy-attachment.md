# ADR 0029: User- and Group-Attached RADIUS Policies

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-010, RAD-POL-005, RAD-POL-006, RAD-POL-007  
Related conformance rows: PRJ-POL-001  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

Shipped RADIUS policy evaluation is client `access_policy_id`, then `fallback_radius_policy_id`, then default deny. Users and groups cannot attach RADIUS rules. [ADR 0014](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0014-neutral-aaa-contract-and-protocol-taxonomy.md) left user/group RADIUS attachment as a Revisit; v1 `User` / `Group` stay TACACS-shaped.

Schema v1 raw user/group types reject unknown fields. Adding `radius_policy_id` there would either break v1 or silently accept a RADIUS key on TACACS-only documents.

## Decision

1. User/group RADIUS attachment is schema **v2 only**: `users[].radius_policy_id`, `groups[].radius_policy_id`. v1 `rawUser` / `rawGroup` reject those keys.
2. Evaluation order is frozen:
   1. user `radius_policy_id` (source `user_policy:<id>`)
   2. each group in `effectiveGroups` (source `group_policy:<id>`)
   3. client endpoint `access_policy_id` (existing)
   4. `fallback_radius_policy_id` (existing)
   5. default deny
3. `effectiveGroups` **must** match `internal/policy/compile.go` (user `group_ids` listed order, then client `default_group_ids` not already present, then sort by ascending group `priority` then `id`). First matching **rule** wins.
4. Unknown policy id is `CONFIG_YAML_INVALID` at validate. REST/MCP `users.*` / `groups.*` accept optional `radius_policy_id` (`PARITY_REQUIRED`, existing `state:write`). Omitted = keep. JSON `null` clears.
5. Stay on schema v2. No v3.

## Alternatives considered

### Add the field to v1 raw user/group

Rejected. v1 stays TACACS-shaped. Unknown-field reject is the contract.

### Evaluate client policy before user/group

Rejected. User/group attachment is useless if the client rule always wins first.

### A different group walk than TACACS `effectiveGroups`

Rejected. Two walks would drift. Reuse the TACACS compile order.

## Consequences

### Positive

- Per-user and per-group RADIUS replies without forking the engine.
- v1 files remain valid and TACACS-only.

### Negative

- v2-only keys. Operators on v1 must convert (or `normalize=true` export) to attach RADIUS policies.
- Existing goldens that would have matched later must be updated in the implementing PR when a new earlier source hits.

## Compatibility impact

No user/group RADIUS fields ship in this documentation change. Shipped walk (client → fallback → deny) stays until the implementing PR.

## Migration

None now. After the implementing PR, add `radius_policy_id` only on v2 documents. Old binaries reject the unknown key. Comment out before downgrade.

## Test impact

- v1 unknown-field reject for `radius_policy_id`.
- Frozen walk goldens under `internal/policy/radius/goldens/`.
- `radius.policy.evaluate` and `radius.access.test` use the same engine.
- REST/MCP/parity for the optional field.

## Documentation impact

CONFIGURATION and OPERATOR policy sections update in the implementing PR. [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) §8 keeps user/group RADIUS rules still-deferred until then.

## Revisit conditions

- Nested groups or role hierarchies are added (out of current product scope).
- A need to invert user vs client precedence — that is a new ADR, not a silent walk change.
