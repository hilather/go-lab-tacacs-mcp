# TacLab threat model

Status: implementation contract  
Last updated: 2026-08-12

This document is the 1.0 security review for TacLab. It links each high-risk
threat to tests or an explicit accepted residual. There is no pager contract;
readiness failure, secret-canary hits, race failures, and conformance FAIL are
blocking.

## 1. Trust boundaries

```text
untrusted TACACS device  --TCP 49 / TLS 300-->  taclabd listeners
untrusted browser        --HTTP 8080 REST/UI-->  admin listener
untrusted MCP client     --POST /mcp---------->  admin listener
operator / CI            --YAML + secret files-> config loader
prometheus scraper       --127.0.0.1:9090----->  metrics listener (optional)
```

Inside the process, adapters converge on `internal/api/operations` and
`internal/aaa`. Policy and credentials never see `net.Conn`, HTTP, or MCP
types. The runtime overlay is memory-only and vanishes on restart.

## 2. Assets

| Asset | Sensitivity | Store |
|---|---|---|
| Legacy TACACS shared secrets | Critical | typed `SharedSecret`; file refs |
| Login verifiers (Argon2id) | High | typed `LoginVerifier` |
| CHAP / MS-CHAP challenge secrets | Critical | typed `ChallengeSecret` |
| ENABLE verifiers | High | typed `EnableVerifier` |
| API bearer token values | Critical | digest after create; one-time return |
| TLS private keys | Critical | file refs; never logged |
| UI session cookies | High | HttpOnly; not in JSON |
| Authorization policy / overlay | Medium | in-memory snapshot |
| Accounting / event ring | Medium | redacted at read |

## 3. Attackers

- Malicious or buggy TACACS NAS on a reachable listener.
- Unauthenticated or under-scoped admin / MCP client.
- Browser on the lab UI (CSRF, XSS, token theft).
- Local process observer (logs, metrics, pprof, crash output).
- Config author who pastes secrets into YAML or reuses keys.

## 4. Abuse cases and mitigations

| ID | Threat | Sev | Mitigation | Evidence |
|---|---|---|---|---|
| TM-01 | Malformed TACACS / length bombs | High | Bounded header-then-body reads; 65536 cap; fuzz | `internal/tacacs/codec` Fuzz*; T89 body bounds |
| TM-02 | Shared-secret mismatch / garbage decode | High | Length-sum check; ERROR; stop new sessions | codec + legacy listener tests |
| TM-03 | Connection / session exhaustion | High | Engine connection semaphores, REST in-flight, idle/lifetime; `Governor.CheckBytes`/`CheckCount` at AAA field bounds | `TestEngineConnectionSaturation`, REST inflight, `checkAuthorFields` / `checkArgBudget` |
| TM-04 | Secret leakage via logs/API/UI/events/metrics/traces | Critical | Typed secrets; canary matrix; write-only OpenAPI | `TestFullCanaryMatrix`, per-adapter canaries |
| TM-05 | Weak / reused / stale legacy secrets | High | Length/class/weak-list; process-local HMAC; lifecycle gauges without `client_id`; TLS-only clients omitted | `TestEvaluateSecretsOmitsTLSOnly`, `TestLifecycleCountsSkipTLSOnly`, `TestLifecycleRejectsClientID` |
| TM-06 | Command auth bypass via normalization | High | No shell parse; two evaluators; golden traces | `testdata/policies/goldens` |
| TM-07 | Stale-write overlay clobber | Medium | `expected_revision` / `If-Match` | state + REST + parity tests |
| TM-08 | REST vs MCP authz drift | High | One registry; parity harness | `internal/api/parity` |
| TM-09 | CSRF / token theft | High | HttpOnly cookie, CSRF, no localStorage | rest session tests |
| TM-10 | TLS downgrade / plaintext on 300 | High | Immediate TLS 1.3; no fallback | tls negatives |
| TM-11 | 0-RTT replay | High | Reject early data | tls handshake tests |
| TM-12 | mTLS identity mix-up | High | SAN + CIDR; unique client; CRL; `VerifyConnection` | tls identity/resume tests |
| TM-13 | Event subscriber resource abuse | Medium | Bounded queues; disconnect slow consumers | events ring tests; reset metric |
| TM-14 | SPA path traversal / embed abuse | Medium | `go:embed` allowlist | rest static tests (PR-19+) |
| TM-15 | Username enumeration | Medium | Uniform FAIL / prompts | aaa auth-flow tests |
| TM-16 | DNS rebinding on `/mcp` | Medium | Origin validation | mcp origin tests |
| TM-17 | Metric cardinality explosion | Medium | Closed label allowlists; no username/IP/command; no `client_id` on lifecycle | `TestForbiddenLabelsDropped` |
| TM-18 | pprof / tracing exposure | Medium | Both off by default; pprof never on admin mux | `TestPprofOffByDefault`, `TestComposedAdminMuxOmitsPprof` |
| TM-19 | Parser hang / alloc blow-up | High | Fuzz time/size caps; body budget | fuzz-smoke in CI |
| TM-20 | Timing side channel on credentials | Medium | Constant-time compare; uniform FAIL | credentials tests |

## 5. Accepted residual risk (1.0)

| Residual | Why accepted | Follow-up |
|---|---|---|
| Co-located legacy + TLS listeners | Lab convenience (ADR 0001); TLS-only profile required | Operator warning; PR-21 TLS-only Compose |
| Lab static bearer (no OAuth PRM) | ADR 0010 | Document 401 without PRM |
| Process-local overlay | Restart restores baseline by design | Persistence is post-1.0 + ADR |
| Metrics `client_id` on connection series | Config-bounded; overflow → `other` | Never on lifecycle/warning series |
| Enabled tracer retains last 256 spans in process | Lab debug only; tracing default off | Do not scrape spans remotely |

No critical or high finding is unowned.

## 6. Operator notes

Example scrapes and alerts (not a pager contract):

- `taclab_connections_accepted_total` / `taclab_connections_rejected_total` by listener.
- `rate(taclab_event_overwritten_total[5m])` — ring loss.
- `taclab_reload_total{result_class="error"}` — failed reload (previous snapshot retained).
- `taclab_secret_lifecycle{status="overdue"}` — rotate legacy keys.
- Do not alert on `client_id` cardinality; that label is bounded and omitted from lifecycle series.

Profiling (`observability.profiling.enabled`) binds only with the dedicated
metrics socket (`127.0.0.1:6060` when metrics are off). Never enable it on a
shared lab host without loopback firewalling.

## See also

- [Canonical design — Security](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md)
- [Architecture — observability](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md)
- [Security policy](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/SECURITY.md)
- [Testing and benchmarks](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TESTING_AND_BENCHMARKS.md)
