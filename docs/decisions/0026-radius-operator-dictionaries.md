# ADR 0026: Fail-Closed Operator RADIUS Dictionaries

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-006  
Related conformance rows: R65-VSA-001  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

The shipped dictionary is built-in IETF MVP only (`DictionaryVersion` `builtin-mvp-1`). Labs cannot name vendor attributes without a code change. [ADR 0015](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0015-radius-codec-attribute-and-dictionary-boundary.md) deferred operator dictionaries because trust, limits, validation, reload, and sensitivity metadata need their own ADR.

FreeRADIUS `$INCLUDE` language is unbounded. Named Cisco and Microsoft attributes land as builtins (ADRs 0027 and 0023) and must not be stolen by an operator file that compiles first.

## Decision

1. Operator dictionaries are **TacLab YAML documents**, add-only, local absolute files, size-capped, fail-closed. Schema v2 `radius_dictionaries` list only. No `http://`, no `s3://`, no `$INCLUDE`.
2. Compile happens in `state.Manager.compile`. Failure does not publish a snapshot (previous snapshot remains).
3. **Reserve** vendor IDs `0` (IETF), `9` (Cisco), and `311` (Microsoft) and names `Cisco-AVPair` / `MS-CHAP-*` **before** those builtins ship. Collision is a compile error.
4. Cannot redefine a built-in named attribute. Cannot set `sensitivity: public` on a name the builtin marks `secret`. Builtin sensitivity wins.
5. Snapshot `DictionaryVersion` stays exactly `builtin-mvp-1` when no operator dictionary compiled. Append `+op:<sorted-ids>:<sha256>` only when at least one operator file is in the merge.
6. `radius.attributes.list` may grow a `source` field (`builtin` | `operator:<id>`). Still `state:read`. No values.
7. Operator `secret` attributes are omitted from events, traces, list values, and UI.

## Alternatives considered

### Accept FreeRADIUS dictionary language

Rejected. `$INCLUDE`, vendor nesting, and `VALUE` enums are an unbounded parser.

### Allow operator files to override IETF / Cisco / Microsoft

Rejected. Sensitivity downgrade and name collision are a secret-leak and a PR race.

### Change `DictionaryVersion` even when the operator list is empty

Rejected. `dictionary_test.go` locks `builtin-mvp-1`.

## Consequences

### Positive

- Labs can name vendor attributes without a code change.
- Built-in secret classes cannot be weakened.

### Negative

- Operators must write TacLab YAML, not copy FreeRADIUS dicts.
- File-count and size caps will reject large vendor packs.

## Compatibility impact

The implementing PR ships the fail-closed loader. Empty operator list keeps `DictionaryVersion` exactly `builtin-mvp-1`.

## Migration

v2 files may list `radius_dictionaries`. v1 files that contain that key fail unknown-field. Comment out before downgrade.

## Test impact

- Compile negatives: reserved vendors, reserved names, sensitivity downgrade, remote path, oversized file, duplicate names.
- `DictionaryVersion` stays `builtin-mvp-1` with an empty operator list.
- Invalid dictionary leaves the previous snapshot active.

## Documentation impact

CONFIGURATION documents the file format and limits. [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) `PRJ-DICT-001` is PASS with compile-fail-closed evidence.

## Revisit conditions

- A reviewed subset of FreeRADIUS dict syntax is required for a lab recipe.
- Additional vendor IDs must be reserved as builtins.
