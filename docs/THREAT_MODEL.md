# TacLab threat model

Status: implementation contract  
Last updated: 2026-08-16

This document is the 1.0 security review for TacLab plus the in-process
RADIUS/UDP lab path. It links each high-risk threat to tests or an explicit
accepted residual. There is no pager contract; readiness failure, secret-canary
hits, race failures, and conformance FAIL are blocking.

RADIUS/UDP is a **controlled-network lab profile** ([ADR 0016](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0016-radius-udp-security-retransmission-and-scope.md)).
It is not advertised as complete RADIUS and is not a substitute for RadSec.

## 1. Trust boundaries

```text
untrusted TACACS device  --TCP 49 / TLS 300-->  taclabd listeners
untrusted RADIUS NAS     --UDP 1812 / 1813--->  taclabd RADIUS access / accounting
untrusted RADIUS DAS tool --UDP 3799---------->  taclabd inbound DAS fixture (index only)
untrusted RadSec NAS     --TCP 2083 TLS 1.3-->  taclabd RadSec (default off)
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
| RADIUS shared secrets | Critical | typed `RADIUSSharedSecret`; distinct purpose |
| RADIUS User-Password (plain and hidden) | Critical | typed buffers; wipe after verify |
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
- Spoofed or buggy RADIUS NAS on a reachable UDP socket (source-IP secret selection).
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
| TM-15 | Username enumeration | Medium | Uniform FAIL / prompts; must-change inspected only after successful verify (UL-TM-01/02/08) | aaa auth-flow + must-change tests |
| TM-16 | DNS rebinding on `/mcp` | Medium | Origin validation | mcp origin tests |
| TM-17 | Metric cardinality explosion | Medium | Closed label allowlists; no username/IP/command; no `client_id` on lifecycle | `TestForbiddenLabelsDropped` |
| TM-18 | pprof / tracing exposure | Medium | Both off by default; pprof never on admin mux | `TestPprofOffByDefault`, `TestComposedAdminMuxOmitsPprof` |
| TM-19 | Parser hang / alloc blow-up | High | Fuzz time/size caps; body budget | fuzz-smoke in CI |
| TM-20 | Timing side channel on credentials | Medium | Constant-time compare; uniform FAIL | credentials tests |
| UL-TM-01 | Username enumeration via distinct LOGIN status/prompt | Medium | Must-change branch only after `Verify*` success | `TestASCIILoginMustChangeWrongPasswordUniform` |
| UL-TM-02 | Username enumeration via PAP `server_msg` | Medium | `Password change required` only after successful verify | `TestPAPWrongPasswordEmptyServerMsg` |
| UL-TM-06 | Granting RADIUS/PAP access when password is expired | High | Post-verify reject in the same merge as the flag; policy not consulted | `TestAuthenticateAccessMustChangeRejectsWithoutPolicy` |
| UL-TM-07 | ENABLE change writing login or vice versa | High | Separate `OverrideEnableVerifier`; login/challenge material stays on file refs | `TestOverrideEnableVerifierClearsMustChange`; `TestEnableMustChangePromptsAndPass` |
| UL-TM-09 | NAS-driven login mutation when `ascii_chpass` is disallowed | High | K13 FAIL + no `OverrideLoginVerifier` | `TestASCIILoginMustChangeWhenCHPASSDisallowed` |

### 4.1 RADIUS/UDP (controlled-network profile)

UDP RADIUS is MD5-era and spoofable. These rows apply only when a RADIUS
listener is enabled. Default example YAML keeps RADIUS `enabled: false`.
Do not treat a green TACACS conformance matrix as RADIUS PASS.

| ID | Threat | Sev | Mitigation | Evidence |
|---|---|---|---|---|
| RAD-TM-01 | Allocation bomb (declared length / TLV walk) | High | 20..4096 both roles; bounded attr walk; fuzz | `internal/radius/codec` Fuzz*; goldens under `testdata/protocol/radius` |
| RAD-TM-02 | Unknown / spoofed source | High | Compiled `RADIUSIndex` LPM before secret or credential work; silent discard | `TestUnknownClientDiscardUsesCompiledRADIUSIndex` |
| RAD-TM-03 | UDP amplification / reflection | High | Reply only after known source + integrity; no reply on MA/authenticator fail; per-source rate; queue drop | spoof + size + `drop_overload` tests |
| RAD-TM-04 | Authenticator confusion | High | Access Request Authenticator is a nonce; Accounting-Request Authenticator is validated; responses always insert Message-Authenticator first | `internal/radius/crypto` vectors |
| RAD-TM-05 | RADIUS secret leakage / cross-purpose reuse | Critical | `PurposeRADIUSSharedSecret`; unique canary; lifecycle without `client_id`; cross-purpose HMAC warn | `TestRADIUSCanaryMatrix`, `TestFullCanaryMatrix` |
| RAD-TM-06 | User-Password leak (plain or hidden) | Critical | hide/unhide + wipe; never log/event/API; unique canary | `TestCanaryUnhiddenPasswordNeverInErrors`, `TestRADIUSCanaryMatrix` |
| RAD-TM-07 | BlastRADIUS / Message-Authenticator / Proxy-State bypass | Critical | Validate every present MA (Access and Accounting); Access require-MA default; `limit_proxy_state`; MA first on every Access and Accounting response | integrity tests; ADR 0016 |
| RAD-TM-08 | Duplicate KDF / duplicate accounting | High | pending/completed retransmission cache + semantic journal excluding Acct-Delay-Time | cache + journal tests |
| RAD-TM-09 | Cache poisoning | High | slot + Request Authenticator + declared-packet digest; invalid MA never reads/inserts/purges | collision/purge tests |
| RAD-TM-10 | Challenge State / Access-Challenge | High | In-memory store: random State, consume-on-use, TTL, bind, capacity fail-closed; raw State never logged. Live Challenge only for opted-in EAP | `R65-ACCESS-004` `PASS`; `TestChallengeIssueConsumeUDPAndTLS`; `TestIndependentTestclientEAPIdentityMD5Wire` |
| RAD-TM-22 | EAP type confusion / tunneled downgrade | High | Unknown types fail closed with generic EAP-Failure; type 25 without `peap` still fail-closes; PEAP Start is opt-in and continuation Rejects | `PRJ-EAP-002`; `TestEAPUnsupportedTypeRejectsWithoutState`; `TestIndependentTestclientPEAPStartWire` |
| RAD-TM-11 | UDP queue / cache / journal exhaustion | High | hard caps; `drop_overload`; journal saturation is fail-open-to-ack | saturation/leak/race |
| RAD-TM-12 | VSA parser confusion | High | nested length checks; unknown VSA preserved raw | VSA corpus/fuzz |
| RAD-TM-13 | Duplicate attribute bypass | High | dictionary cardinality; conflicting auth evidence → Access-Reject | access reject tests |
| RAD-TM-14 | Trust NAS-IP / NAS-Identifier for the secret | High | Source IP vs compiled index selects the endpoint first | spoofed NAS tests |
| RAD-TM-15 | Accounting spoof / false dedupe / replay | High | Accounting authenticator first; journal excludes Delay-Time; interim counters not collapsed | delay-time + interim tests |
| RAD-TM-16 | Sensitive attribute export | Critical | sensitivity metadata + canaries | REST/MCP/UI/event scans |
| RAD-TM-17 | Metric cardinality | Medium | Closed `protocol` / `role` / `reason_code` / `outcome` (and `code` / `result` / `type`); no `client_id`, User-Name, or IPs on RADIUS series | `TestRADIUSSeriesRejectClientIDUsernameAndIP` |
| RAD-TM-18 | Reload vs cached replies | Medium | cache stores exact bytes + originating revision | retry-across-reload (later) |
| RAD-TM-19 | Cross-protocol secret mix | High | Distinct purposes; no implicit TACACS secret for RADIUS | negative config tests |
| RAD-TM-20 | UDP mistaken for a secure transport | High | Validate/status/UI/docs warnings; 1812/1813/3799/2083 stay off the public internet | ADR 0016; OPERATOR §1.1 |
| RAD-TM-21 | UDP Challenge amplification | High | Challenge only after known client + valid MA; capacity reject not silent flood | challenge store tests; ADR 0021 |
| RAD-TM-23 | MS-CHAP VSA material leak | Critical | Wipe assembled buffers; never event/log/UI MS-CHAP VSAs | canary; ADR 0023 |
| RAD-TM-24 | Spoofed DAC CoA/Disconnect | Critical | MA required; unknown client discard; no `allow_missing` on CoA/RadSec; DAC uses the client's UDP RADIUS secret | dynauth negatives; ADR 0024 |
| RAD-TM-30 | Inbound DAS fixture treated as a kick | High | :3799 is RFC 5176 echo only; mutates the in-memory index; never forwards to a NAS | OPERATOR + UI residual copy; ADR 0024 |
| RAD-TM-25 | Dictionary file as attack payload | High | Absolute path, size caps, YAML-only, no IETF override, fail closed | compile negatives; ADR 0026 |
| RAD-TM-26 | Operator dict marks User-Password public | Critical | Forbidden; builtin sensitivity wins | validate test; ADR 0026 |
| RAD-TM-27 | RadSec mTLS as “UDP but encrypted” | Medium | Docs/UI: TLS 1.3 stream on TCP 2083; UDP warning remains | operator + UI tests; ADR 0025 |
| RAD-TM-28 | Session-index / challenge-store exhaustion | High | Hard caps; no evict-to-admit on Challenge | saturation tests |
| RAD-TM-29 | Proxy/open relay | Critical | Not implemented; unknown `proxy` key fails compile | config reject; ADR 0028 |

Replay of an exact Access or Accounting datagram hits the completed cache and
does not re-run the password KDF or append a second event. A Delay-Time retry
mints a new Accounting-Response for the new Identifier/Request Authenticator
without a second ring record. Ambiguous accounting identity (no
`Acct-Session-Id` and no NAS identity) is fail-open-to-ack and sample-capped so
it cannot fill the shared event ring.

## 5. Accepted residual risk (1.0)

| Residual | Why accepted | Follow-up |
|---|---|---|
| Co-located legacy + TLS listeners | Lab convenience (ADR 0001); TLS-only profile required | Operator warning; PR-21 TLS-only Compose |
| Lab static bearer (no OAuth PRM) | ADR 0010 | Document 401 without PRM |
| Process-local overlay | Restart restores baseline by design | Persistence is post-1.0 + ADR |
| Metrics `client_id` on connection series | Config-bounded; overflow → `other` | Never on lifecycle/warning **or RADIUS** series |
| Enabled tracer retains last 256 spans in process | Lab debug only; tracing default off | Do not scrape spans remotely |
| RADIUS/UDP on a reachable socket | Lab interop (ADR 0016); MD5/HMAC-MD5, spoofable datagrams, cleartext attributes | Default `enabled: false`; require Message-Authenticator; keep 1812/1813/3799/2083 off the public internet |
| Ambiguous accounting identity fail-open-to-ack | Avoids NAS retry-storm; ring append is sampled | Operators who need strict dedupe raise journal caps |

No critical or high finding is unowned. RADIUS listeners being present does
**not** mean RADIUS conformance is complete.

## 6. Operator notes

Example scrapes and alerts (not a pager contract):

- `taclab_connections_accepted_total` / `taclab_connections_rejected_total` by listener.
- `rate(taclab_event_overwritten_total[5m])` — ring loss.
- `taclab_reload_total{result_class="error"}` — failed reload (previous snapshot retained).
- `taclab_secret_lifecycle{status="overdue"}` — rotate legacy keys.
- `rate(taclab_protocol_discards_total{protocol="radius"}[5m])` — UDP integrity / unknown-client / overload.
- `taclab_radius_cache_saturations_total` / `taclab_radius_journal_saturations_total` — raise caps or rate-limit the NAS.
- Do not alert on `client_id` cardinality; that label is bounded and omitted from lifecycle **and RADIUS** series.

Profiling (`observability.profiling.enabled`) binds only with the dedicated
metrics socket (`127.0.0.1:6060` when metrics are off). Never enable it on a
shared lab host without loopback firewalling.

## See also

- [Canonical design — Security](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md)
- [Architecture — observability](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md)
- [Security policy](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/SECURITY.md)
- [Testing and benchmarks](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TESTING_AND_BENCHMARKS.md)
