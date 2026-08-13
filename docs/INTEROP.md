# TacLab 1.0 interoperability notes

Status: 1.0 qualification record  
Date: 2026-08-13  
Normative matrices: [TACACS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TACACS_CONFORMANCE.md) §16, generated [conformance.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/conformance.md)

## Policy

1.0 **requires** an independent software TACACS peer. Cisco IOS/IOS-XE and a second NOS family are **optional** and may be skipped when hardware is absent. A skip is not server conformance evidence.

Shared-codec loopback (`internal/tacacs/codec` talking to itself) is **not** the software peer.

## Matrix

| Case | Legacy | TLS | Authn | Authz | Acct | Single-connect | Status |
|---|---:|---:|---|---|---|---:|---|
| Independent Go test client (`internal/tacacs/testclient`, separate codec copy) | Yes | Yes | ASCII, PAP, CHAP, MS-CHAP v1/v2, ENABLE, CHPASS | session + command | START/STOP/WATCHDOG + invalid flags | Yes | **PASS** |
| External open-source TACACS daemon/client (tac_plus, ntc, …) | — | — | — | — | — | — | **SKIP** — not run in this environment; in-tree testclient is the required software peer |
| Cisco IOS / IOS-XE (or equivalent) | — | — | — | — | — | — | **SKIP** — no lab hardware |
| Second NOS (Junos, EOS, …) | — | — | — | — | — | — | **SKIP** — no lab hardware |
| Malformed / raw packet harness | Yes | Yes | negative | negative | negative | negative | **PASS** (`testdata/protocol/**`, fuzz seeds) |

## Software peer evidence

| ID | Evidence |
|---|---|
| Independent codec | `internal/tacacs/testclient/codec` does not import `internal/tacacs/codec` |
| Legacy e2e | `cmd/taclabd.TestVerticalSkeletonE2E`, `TestRemainingAuthFlowsE2E` |
| TLS client role | T98-ROLE-001–005: `TestDialTLSBeginsImmediately`, `TestDialTLSNoFallbackOnPlaintextPeer`, `TestServerIdentityMatrix`, `TestTLSForcesUnencryptedAndRejectsClearFlag`, `TestDialTLSClientHelloHasNoEarlyData` |
| Compose LAB-* | `LAB-AUTH-*`, `LAB-AUTHZ-*`, `LAB-ACCT-*`, `LAB-TLS-*` via `make lab-test` |

Peer versions recorded for this freeze:

| Component | Version |
|---|---|
| TacLab | 1.0 qualification (`git describe` at freeze) |
| Go | 1.24.5 |
| Testclient | in-tree, this repository |
| Device NOS | n/a (skipped) |

## Device skip procedure

When hardware appears:

1. Record platform, software release, transport, methods, author form, acct flags, single-connect behavior.
2. Capture sanitized traces (no secrets).
3. Turn every defect into a golden fixture under `testdata/protocol` or `testdata/vendors`.
4. Update this file and tick the matrix row. Do not mark a MUST row PASS from a device skip.

## Known interop limits (not device skips)

| Limit | Disposition |
|---|---|
| RFC 7924 Cached Information | [ADR 0003](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0003-cached-information.md) |
| Configurable TLS 1.3 cipher lists | [ADR 0004](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0004-tls13-cipher-policy.md) |
| Ticket lifetime other than 0 / 168h | [ADR 0005](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0005-ticket-lifetime.md) |
| External TLS PSK / raw public keys | [ADR 0006](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0006-external-psk-rpk.md) `DEFERRED_MAY` |
| MCP OAuth protected-resource metadata | [ADR 0010](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0010-lab-static-bearer.md) |
| ASCII/PAP compile warning | [ADR 0012](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md) |
