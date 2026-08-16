# ADR 0027: Named Cisco-AVPair with Independent Fixtures

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-007, RAD-CODEC-008  
Related conformance rows: R65-VSA-001  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)  
Supersedes: [ADR 0015](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0015-radius-codec-attribute-and-dictionary-boundary.md) decision 4 and its Revisit condition for named `Cisco-AVPair`

## Context

[ADR 0015](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0015-radius-codec-attribute-and-dictionary-boundary.md) decision 4 stated:

> Named `Cisco-AVPair` decoding is **not** in MVP. It is a later release after independent Cisco IOL vectors. Reply profiles may emit a raw VSA via `{vendor, code, value_hex}` only.

ADR 0015 Revisit included:

> Independent Cisco IOL vectors exist for named `Cisco-AVPair`.

This repository does not vendor IOL or refplat images. `make cisco-lab` is skip-when-absent and a skip is not Cisco PASS and not RADIUS PASS. Waiting on IOL vectors blocked named decode indefinitely.

Independent `internal/radius/testclient` fixtures can prove named encode/decode without a Cisco image.

## Decision

This ADR **quotes and replaces** ADR 0015 decision 4 and the IOL-gated Revisit for named `Cisco-AVPair`.

1. Named `Cisco-AVPair` (vendor 9, vendor-type 1) is implemented with independent `internal/radius/testclient` fixtures. That evidence is sufficient to mark the project Cisco-AVPair row `PASS` when the implementing PR lands.
2. `make cisco-lab` IOL remains optional `interop:`. A skip is **not** Cisco PASS and **not** RADIUS PASS. Do not mark a conformance row `PASS` with only an IOL skip. Do not add a Cisco IOL image to the repo.
3. Built-in (not operator-dict) entry: vendor `9`, vendor-type `1`, name `Cisco-AVPair`, `kind: text`, `cardinality: multi`, `sensitivity: restricted`. Reply profiles accept the named form and the existing raw `{ vendor: 9, code: 1, value_hex }` form; both must round-trip to the same wire.
4. Vendor 9 and the name `Cisco-AVPair` are reserved from operator dictionaries (ADR 0026) even before the builtin ships.
5. TASKS §22.4 drops the wording “after independent Cisco IOL vectors.”

ADR 0015 decisions 1–3 and 5 (in-tree codec, `domain.AVPair` TACACS-only, built-in IETF MVP for the first release, independent testclient) remain accepted.

## Alternatives considered

### Keep raw VSA until IOL evidence exists (ADR 0015 option)

Rejected. This repo does not vendor IOL. The IOL gate blocked named decode indefinitely.

### Require IOL PASS to flip the Cisco-AVPair row

Rejected. Skip-when-absent would make the row unclosable in CI.

## Consequences

### Positive

- Named reply profiles can say `Cisco-AVPair = shell:priv-lvl=15` after the implementing PR.
- Evidence is reproducible without a proprietary image.

### Negative

- Device interop for Cisco-AVPair remains optional and skippable.
- Operators must not treat independent fixtures as Cisco NAS PASS.

## Compatibility impact

No named decode ships in this documentation change. Raw VSA framing stays required and unchanged.

## Migration

None now. After the implementing PR, reply profiles may use the named form. Old binaries that only accept raw `{vendor, code, value_hex}` keep working if operators stay on the raw form.

## Test impact

- Independent goldens plus `testclient` Cisco TLV encoder (must not import production `codec` / `crypto` / `server`).
- Named and raw forms round-trip to the same wire.
- Optional `make cisco-lab` RADIUS scenario SKIP without `TACLAB_IOL_IMAGE`.
- Shared-codec loopback is not sufficient.

## Documentation impact

ADR 0015 is annotated so decision 4 / IOL Revisit point here. [docs/TASKS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TASKS.md) §22.4 and [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) §8 drop the IOL gate. INTEROP honesty stays: skip is not PASS.

## Revisit conditions

- Additional named Cisco vendor-types are required.
- An interop program makes IOL a required (not skippable) evidence class — that would be a new ADR, not a silent reopen of the IOL gate.
