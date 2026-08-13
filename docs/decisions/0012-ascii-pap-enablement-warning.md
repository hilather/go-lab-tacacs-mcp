# ADR 0012: ASCII/PAP Enablement Warning

Status: Accepted  
Date: 2026-08-13  
Decision owners: TacLab maintainers  
Related tasks: P5.9, P15.1, P16.1  
Related conformance rows: T89-SEC-002  
Disposition: DISPOSITIONED_SHOULD

## Context

RFC 8907 SHOULD warn when ASCII or PAP (non-challenge) methods are enabled and document that those methods should be used only when a device cannot do CHAP/MS-CHAP. TacLab 1.0 is a lab appliance whose reference baseline enables ASCII and PAP so device login, GETUSER/GETPASS, and CHPASS can be exercised.

A compile-time or startup warning on every reference-lab start would fire continuously and train operators to ignore diagnostics. Challenge-only clients already exist and produce RESTART (not FAIL) for ASCII/PAP.

## Decision

1. **Do not** emit a compile/startup warning merely because an enabled client or user allows ASCII or PAP.
2. Operator documentation (`docs/OPERATOR.md`, `docs/CONFIGURATION.md`) states that ASCII/PAP are lab compatibility methods and must not be treated as protected-network authentication.
3. The reference example comments the `allowed_methods` list and points at the challenge-only profile.
4. Administrators restrict methods per client (`authentication.allowed_methods`). A challenge-only client rejects ASCII/PAP/ENABLE/CHPASS with RESTART.
5. T89-SEC-002 is `DISPOSITIONED_SHOULD`. Do not mark it PASS from challenge-only tests alone.

## Alternatives considered

### Warn on every snapshot that allows ASCII/PAP

Rejected. The reference lab would always warn. Operators would hide or ignore the message.

### Fail closed unless challenge-only

Rejected. That would break the required ASCII/PAP/CHPASS lab flows.

## Consequences

### Positive

- Lab examples stay usable.
- Challenge-only remains a first-class, tested profile.

### Negative

- Logs do not remind an operator who copies the example into a more exposed network.

## Compatibility impact

None. Method policy and RESTART/FAIL/ERROR mapping are unchanged.

## Migration

None. Operators who want the restriction set `allowed_methods` to challenge types only.

## Test impact

- `TestChallengeOnlyRestartsNonChallenge` remains the enforcement evidence.
- No new compile warning assertion.

## Documentation impact

This ADR is the disposition for T89-SEC-002. Operator docs must keep the ASCII/PAP warning text.

## Revisit conditions

- A production-like profile becomes the default.
- An operator requests an opt-in `warn_on_non_challenge_methods` compile diagnostic.
