# ADR 0015: RADIUS Codec, Attribute, and Dictionary Boundary

Status: Accepted  
Date: 2026-08-14  
Decision owners: TacLab maintainers  
Related tasks: RAD-CODEC-001, RAD-CODEC-002, RAD-CODEC-003, RAD-CODEC-004, RAD-CODEC-008  
Related conformance rows: R65-PKT-001, R65-ATTR-001, R65-ATTR-002, R65-VSA-001, R65-PROXY-001  
Source pin: `3322c26bd78969498e6fa0cd6e4b30902d5c8a94`

## Context

The existing TACACS implementation owns an in-tree codec and keeps an independent test-client codec. RADIUS has a mature Go ecosystem, but library quality, RFC coverage, security posture, allocation behavior, maintenance, and type leakage must be evaluated. Existing `domain.AVPairs` preserves order/duplicates but encodes TACACS `name=value` / `name*value` semantics and cannot safely represent binary RADIUS attributes.

## Decision

The project owns the `internal/radius` facade, packet/attribute behavior, limits, errors, dictionary metadata, crypto policy, and tests.

1. In-tree RADIUS codec is the default. Spike `RAD-CODEC-001` must still run; a third-party implementation may be wrapped only if:
   - no third-party type escapes `internal/radius/codec`;
   - bounded parsing/allocation and required raw preservation are enforceable;
   - authenticators and Message-Authenticator can be independently tested;
   - unknown attributes, duplicates, ordering, VSA framing, and future extended attributes are not lost;
   - licensing and maintenance are acceptable.
2. RADIUS attributes are `internal/radius/attribute` (raw, typed, policy/config). `domain.AVPair` stays TACACS-only.
3. Built-in dictionary only for the first release. IETF MVP attributes are named. Vendor-Specific framing and raw unknown/VSA preservation are mandatory.
4. Named `Cisco-AVPair` decoding is **not** in MVP. It is a later release after independent Cisco IOL vectors. Reply profiles may emit a raw VSA via `{vendor, code, value_hex}` only.
   **Superseded 2026-08-16 by [ADR 0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md):** named `Cisco-AVPair` uses independent `internal/radius/testclient` fixtures; IOL is optional `interop:` and a skip is not PASS. The quoted text above is historical MVP scope only.
5. Independent `internal/radius/testclient` codec is mandatory evidence and must not import production `codec`, `crypto`, or `server`.

## Alternatives considered

### Reuse `domain.AVPair` for RADIUS

Rejected. Separators cannot represent binary TLVs or VSAs.

### Adopt a third-party codec as the public type

Rejected. Same isolation policy as [ADR 0007](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0007-codec-approach.md) for TACACS.

### Operator-supplied custom dictionaries in MVP

Rejected. Trust, limits, validation, reload, and sensitivity metadata require a later ADR.

### Named Cisco-AVPair in MVP

Rejected for MVP. User decision 2026-08-14: wait for independent IOL vectors. **Superseded for the remaining-work program by [ADR 0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md)** (independent fixtures; IOL skip is not PASS).

## Consequences

### Positive

- The project can replace a dependency without changing application contracts.
- Security and conformance evidence remain project-owned.
- Unknown attributes and VSAs survive round-trip.

### Negative

- A small wrapper cost is accepted to prevent domain contamination.
- Named vendor dictionaries waited on interop evidence in MVP. [ADR 0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md) replaces the IOL gate for named `Cisco-AVPair`.

## Compatibility impact

None on TACACS AV-pair encode/decode or policy goldens.

## Migration

None. Dictionary version is an immutable snapshot field (`DictionaryVersion`) when RADIUS compile lands.

## Test impact

- Independent testclient encode/decode is required before advertising access or accounting.
- Fuzz seeds for packet, attribute, and VSA decode.
- Packet-role legality is a compile error, not a runtime surprise.

## Documentation impact

Attribute and dictionary inventory is in [docs/designs/radius-authentication.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-authentication.md) §5.2 and [docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md).

## Revisit conditions

- ~~Independent Cisco IOL vectors exist for named `Cisco-AVPair`.~~ **Replaced by [ADR 0027](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0027-named-cisco-avpair-independent-fixtures.md).** Named decode evidence is independent `testclient` fixtures. IOL remains optional `interop:`; a skip is not Cisco PASS and not RADIUS PASS.
- The codec spike proves a wrapped library beats in-tree on bounds/MA/raw preservation without type leakage.
- Interop requires a reviewed custom-dictionary ADR ([ADR 0026](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0026-radius-operator-dictionaries.md) is that ADR for TacLab YAML dictionaries).
