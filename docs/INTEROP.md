# TacLab 1.0 interoperability notes

Status: 1.0 qualification record (TACACS) plus RADIUS software-peer record  
Date: 2026-08-14  
Normative matrices: [TACACS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TACACS_CONFORMANCE.md) §16, [RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md), generated [conformance.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/generated/conformance.md)

## Policy

1.0 **requires** an independent software TACACS peer. Cisco IOS/IOS-XE and a second NOS family are **optional** and may be skipped when hardware is absent. A skip is not server conformance evidence.

Shared-codec loopback (`internal/tacacs/codec` talking to itself) is **not** the software peer.

## Matrix

| Case | Legacy | TLS | Authn | Authz | Acct | Single-connect | Status |
|---|---:|---:|---|---|---|---:|---|
| Independent Go test client (`internal/tacacs/testclient`, separate codec copy) | Yes | Yes | ASCII, PAP, CHAP, MS-CHAP v1/v2, ENABLE, CHPASS | session + command | START/STOP/WATCHDOG + invalid flags | Yes | **PASS** |
| External open-source TACACS daemon/client (tac_plus, ntc, …) | — | — | — | — | — | — | **SKIP** — not run in this environment; in-tree testclient is the required software peer |
| Cisco IOS / IOS-XE via Containerlab IOL (`cisco_iol`, vrnetlab from CML refplat) | Yes (legacy TCP) | not in this lab | login + ENABLE when the image is present | if the image offers exec/command | if the image sends acct | device | **SKIP** when `containerlab` or `TACLAB_IOL_IMAGE` is absent (`make cisco-lab`). A skip is **not** Cisco PASS. |
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
| Go | 1.25.0 |
| Testclient | in-tree, this repository |
| Device NOS | n/a (skipped) |

## Optional Containerlab + IOL lab

Operators who have a licensed CML-Free (or CML) refplat can build a local `vrnetlab/cisco_iol:<tag>` image and run `make cisco-lab`. Procedure: [deployments/containerlab/README.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/deployments/containerlab/README.md).

When hardware or that image appears:

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
| RADIUS Access-Challenge / EAP termination / CoA / RadSec | [ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md) |

## RADIUS software peer

RADIUS **requires** an independent software peer. Shared-codec loopback (`internal/radius/codec` talking to itself) is **not** that peer. External `radclient` is the Q-010 mature client when installed; a skip is **not** RADIUS PASS and is **not** advertised completeness.

Do **not** tell peers to disable response Message-Authenticator checking.

### Matrix

| Case | Access | Accounting | MA request | MA response | Status |
|---|---|---|---|---|---|
| Independent Go test client (`internal/radius/testclient`, separate codec copy) | PAP Access-Accept | Start + Accounting-Response | Yes | Required | **PASS** (`TestIndependentTestclientPAPAndAccountingOnUDP`) |
| FreeRADIUS 3.2.5+ `radclient` / `radtest` | PAP / CHAP | Start/Stop/Interim with MA | Required | Required | **SKIP** — `radclient` not on PATH in this environment (`TestExternalRadclientAccessAndAccounting`). Required peer: FreeRADIUS 3.2.5+ sending `Message-Authenticator` and validating TacLab Access and Accounting responses. |
| Cisco IOS / IOS-XE via Containerlab IOL | if image sends RADIUS | if image sends acct | device | device | **SKIP** when `containerlab` or `TACLAB_IOL_IMAGE` is absent (`make cisco-lab`). A skip is **not** Cisco PASS and is **not** RADIUS PASS. |
| Second NAS (Junos, EOS, …) | — | — | — | — | **SKIP** — no lab hardware |

### Software peer evidence

| ID | Evidence |
|---|---|
| Independent codec | `internal/radius/testclient/codec` does not import `internal/radius/codec`, `crypto`, `server`, or `udp` |
| Independent UDP e2e | `internal/radius/udp.TestIndependentTestclientPAPAndAccountingOnUDP` |
| External radclient | `internal/radius/udp.TestExternalRadclientAccessAndAccounting` (skip unless `radclient` is on `PATH`) |
| Compose LAB-* | `LAB-RADIUS-001`, `LAB-RADIUS-002`, `LAB-RADIUS-ONLY` via `make lab-test` (REST diagnostic path; not a wire-peer substitute) |

Peer versions recorded for this freeze:

| Component | Version |
|---|---|
| TacLab | RADIUS evidence attach (`git describe` at this change) |
| Go | 1.25.13 |
| Testclient | in-tree, this repository |
| FreeRADIUS `radclient` | n/a (skipped: not installed) |
| Device NOS | n/a (skipped) |

When `radclient` is installed (FreeRADIUS 3.2.5+ recommended):

1. Run `go test ./internal/radius/udp -run TestExternalRadclientAccessAndAccounting`.
2. Record the `radclient -v` (or package) version here.
3. Capture sanitized traces (no secrets).
4. Do not mark a MUST row PASS from this skip alone.

Do **not** advertise complete RADIUS while Access-Challenge is `DEFERRED_MAY`, `radclient` is skipped, or `system.build.get` RADIUS status is `partial`.
