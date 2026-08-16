# ADR 0019: Force Login-Class Lock and Lab/Vendor In-LOGIN GETPASS

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: UL-GOV-001, UL-MDL-001, UL-AAA-001, UL-AAA-002, UL-AAA-003, UL-API-001, UL-API-002, UL-RAD-001  
Related conformance rows: T89-FLOW-013, T89-FLOW-014, T89-FLOW-015, PRJ-UL-001

## Context

Operators and QA agents can disable a user, expire the **account** window (`restrictions.valid_before`), rotate write-only secrets, and run client-initiated ASCII CHPASS. They cannot mark a password as expired so that the **next successful login must change it**.

`restrictions.valid_before` is the wrong tool. Credential lookup maps it to `KindExpired` **before** the password is verified. TACACS stays a uniform FAIL, and authorization denies with `user not valid at evaluation time`. That is account expiry, not password expiry.

RFC 8907 has no `PASSWORD_EXPIRED` status. ASCII LOGIN (§5.4.2.1) obtains **the** password via GETPASS and ends PASS, FAIL, or ERROR. ASCII CHPASS (§5.4.2.7) is the defined change-password action. ENABLE (§5.4.2.6) is privilege elevation, not enable-secret rotation. There is no RFC CHPASS-for-enable.

TacLab today only mutates the login verifier via `flowCHPASS` and `OverrideLoginVerifier`. CHPASS is client-initiated (`TAC_PLUS_AUTHEN_CHPASS`). The server never forces a change conversation after LOGIN. Overlay is memory-only; the YAML baseline is never rewritten.

MCP clients speak `POST /mcp` (`taclab.*` tools). Hosted agents cannot send TACACS CONTINUE packets on ports 49/300.

## Decision

1. **No new TACACS status.** Wire statuses stay PASS, FAIL, GETDATA, GETUSER, GETPASS, RESTART, and ERROR. FOLLOW is still never emitted. Do not invent `PASSWORD_EXPIRED` / `0x08`.
2. **In-LOGIN / in-ENABLE GETPASS is a lab/vendor extension** on the generic GET* conversation. It is **not** RFC 8907 LOGIN (§5.4.2.1) or ENABLE (§5.4.2.6) semantics. After a successful ASCII LOGIN verify with `must_change_login` (or successful ENABLE verify with `must_change_enable`), TacLab **may** continue the same session with extra GETPASS new/confirm. Some NAS may ignore extra GETPASS; primary evidence is `internal/tacacs/testclient` plus AAA unit tests. Optional `make cisco-lab` is **not** Cisco PASS for this feature.
3. **RFC change-password remains CHPASS** (§5.4.2.7). Client-initiated CHPASS prompts and goldens stay `"Password: "`. Successful CHPASS publish uses the existing `OverrideLoginVerifier` path and clears `must_change_login`.
4. **In-ENABLE change is a new TacLab capability** with **no** RFC or existing TacLab CHPASS analogue (`CHPASS` + `authen_service=ENABLE` remains FAIL). It must not gate the login-class fail-closed merge.
5. **`must_change_login` is an identity lock (K7)** on all login-class methods after successful verify: ASCII, PAP, CHAP, MS-CHAP, and RADIUS access. It does **not** apply to ENABLE. `must_change_enable` is enable-secret only. Flags are top-level user booleans (default `false`), not `restrictions` fields and not nested under write-only secret objects. Inspect flags only after `Verify*` returns nil, on the session-bound snapshot. `KindExpired` stays account-window only and is not a must-change `FailureKind`.
6. **In-LOGIN new/confirm requires `ascii_chpass` in the client’s effective `allowed_methods` (K13)** (empty list = all allowed). If ASCII LOGIN is allowed but `ascii_chpass` is not, after successful verify + flag the server **FAIL**s with printable `server_msg=Password change required` and **does not mutate**. Alternative G (mutate anyway) is rejected. In-ENABLE is gated only by `enable` already being allowed; do not invent `enable_chpass`.
7. **YAML-set flags are durable; MCP/REST-set flags and published PHCs are overlay-only (K16).** `runtime.reset` / restart restores the YAML verifier **and** the YAML flag. In-LOGIN / CHPASS / in-ENABLE never write the baseline file.
8. **CHPASS PASS always sets event `reason_code=password_changed` (Q2 closed)**, even if the flag was already false. In-LOGIN success is `ascii_login` + `password_changed`. PAP/CHAP/MS-CHAP must-change is `fail` + `password_change_required`. Metrics `result_class` stays the existing closed set; terminal must-change FAIL is `fail`.
9. **MCP owns fixture + assert + admin rotate.** Use existing `taclab.users.update` / `taclab.users.get` / `taclab.authentication.test` (REST/MCP `PARITY_REQUIRED`). Do **not** invent `taclab.qa.*` tools. GETPASS new/confirm is NAS / `internal/tacacs/testclient` only. MCP finishes a force-change by rotating `login` / `enable` (a non-nil secret patch clears the corresponding flag unless the same patch sets the flag true).
10. **FAIL-only remains the PAP / CHAP / MS-CHAP / RADIUS behavior.** After successful verify + `must_change_login`: TACACS FAIL with `server_msg=Password change required`; RADIUS Access-Reject `reject_password_change_required` with **no** extra attributes, **no** Microsoft Password-Expired VSA, and **no** Access-Challenge (still [ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md)). Wrong password / unknown / disabled / restricted / account-expired stay uniform FAIL with empty `server_msg`.

`authentication.test` gains a fifth status, `must_change`, after successful verify + the applicable flag. That value is **not** a TACACS or RADIUS packet status. RADIUS `radius.access.test` surfaces `reason_code=reject_password_change_required` instead.

Closed product questions for v1:

- **Q1:** Reference Compose baseline stays recipes-only. Do not add a `qa-expired-login` user to compose `taclab.yaml`.
- **Q2:** CHPASS PASS `reason_code` is always `password_changed`.
- **Q3:** A `must_change_mode: in_login | fail_signal` switch is **not** v1. See Revisit.

## Alternatives considered

### A. FAIL + `server_msg` only; require the NAS to start CHPASS

Rejected as the primary ASCII LOGIN behavior. Closer to some ACS/ISE “password expired” replies, but the product request is to *change*, not just fail. Kept as the PAP/CHAP/MS-CHAP/RADIUS behavior and as the K13 path when `ascii_chpass` is disallowed.

### B. Dedicated `taclab.users.qa.apply_fixture` / `taclab.qa.*` tools

Rejected. Parallel admin surface; still `PARITY_REQUIRED`; drifts from operator fields. QA uses the same `users.*` fields plus documented recipes.

### C. Put flags on `restrictions` or under `credentials.login`

Rejected. Restrictions are fail-closed **before** verify (`KindExpired`). Nesting under `login` mixes write-only secrets with readable state.

### D. Check must-change inside `credentials.lookup` as `KindMustChange`

Rejected. CHPASS could not verify the old password; LOGIN could not wait until after verify (enumeration).

### E. Runtime clock / as-of MCP tool for expiry tests

Deferred. Global clock mutation is dangerous in a shared lab. Tests already inject `domain.Clock`.

### F. Ship Microsoft Password-Expired VSA / Access-Challenge now

Rejected for this pack. Access-Challenge stays deferred ([ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md)). Follow-up remains `RAD-EXT-001`.

### G. In-LOGIN GETPASS without requiring `ascii_chpass`

Rejected. The side effect is CHPASS (`OverrideLoginVerifier`). Operators who omit `ascii_chpass` to forbid NAS-driven login-secret mutation must not be bypassed. K13 FAIL + no mutation; MCP rotate still works.

### H. `authentication.test` stays `pass` + a `must_change` bool

Rejected. Recipes need one token. Keep fifth status `must_change` and document the wire mapping.

## Consequences

### Positive

- Operators and MCP agents can fixture a login-class lock without expiring the account window.
- NAS / testclient can finish ASCII LOGIN change in one session when `ascii_chpass` is allowed.
- PAP, CHAP, MS-CHAP, and RADIUS fail closed after successful verify.
- REST and MCP stay on the same typed `users.*` operations. No `taclab.qa.*` surface.
- YAML baseline remains immutable; overlay reset is still the restore path.

### Negative

- ASCII LOGIN **may** emit extra GETPASS (vendor extension). Some NAS may not handle it.
- A client `allowed_methods` list without `ascii_chpass` cannot complete in-LOGIN mutation.
- PAP / CHAP / RADIUS cannot complete an interactive change.
- Public User schema grows two booleans. `authentication.test` gains a fifth status; existing four-value clients see an unknown status.
- YAML-set flags “un-change” the password on `runtime.reset` unless the new secret is also written into YAML.

## Compatibility impact

Additive. Omitted YAML/JSON booleans default false. Existing `schema_version: 1` and `2` files stay valid. Old clients that omit the new keys keep working. Overlay reset restores YAML, including YAML-set flags and old verifiers. Old binaries that see the new YAML keys fail unknown-field (strict loader).

No change to TACACS status codes, CHPASS prompt goldens, or RADIUS Access-Challenge deferral.

## Migration

None required. Operators who need the behavior set `must_change_login` / `must_change_enable` via YAML, REST, or MCP. Rollback: comment out the keys before downgrading to a binary that rejects unknown fields. Overlay flags vanish on `runtime.reset`.

## Test impact

User-lifecycle pack `UL-*` in [docs/TASKS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TASKS.md) §23.

| Row | Requirement |
|---|---|
| T89-FLOW-013 | ASCII LOGIN after successful password + `must_change_login` **may** continue with GETPASS new/confirm (vendor extension) when `ascii_chpass` is allowed; otherwise FAIL + `Password change required` |
| T89-FLOW-014 | PAP/CHAP/MS-CHAP after successful verify + `must_change_login` FAIL with fixed `server_msg`; wrong password remains empty `server_msg` |
| T89-FLOW-015 | ENABLE after successful secret + `must_change_enable` continues GETPASS new/confirm (TacLab extension; not RFC ENABLE). Does not gate login-class merge |
| PRJ-UL-001 | RADIUS Access-Reject `reject_password_change_required` after good PAP/CHAP + `must_change_login`; no extra attrs |

CHPASS success evidence must include `reason_code=password_changed`. Combined `KindExpired` + flag must stay uniform FAIL. Login-class fail-closed (TACACS + RADIUS reject + `authentication.test` `must_change`) lands as one vertical.

## Documentation impact

This ADR is the contract for the new fields and the lab/vendor LOGIN-after-verify GETPASS extension. CANONICAL_DESIGN LOGIN table, TACACS/RADIUS conformance rows, CONFIGURATION, OPERATOR recipes, OpenAPI/MCP enums, and CHANGELOG update in the implementing PRs. Do not mark RADIUS complete. Do not add a compose fixture user (Q1).

## Revisit conditions

If Cisco IOL evidence shows LOGIN extra GETPASS is unusable, consider a documented `must_change_mode: in_login | fail_signal` (new ADR; do **not** silently switch). Access-Challenge / Password-Expired VSA remain a later RADIUS ADR (`RAD-EXT-001`).
