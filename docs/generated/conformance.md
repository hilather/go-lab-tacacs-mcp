# Generated TACACS+ conformance inventory

Do not hand-edit this file. Run `make generate`.

Sources: `testdata/conformance/rfc8907.yaml`, `testdata/conformance/rfc9887.yaml`

Status columns start `NOT_STARTED` with empty evidence.

## RFC 8907

RFC 8907 TACACS+

| ID | Level | Status | Requirement | Required evidence |
|---|---|---|---|---|
| T89-H-001 | PROJECT MUST | NOT_STARTED | Support TACACS+ major version 0xc and minor versions 0 and 1 in their valid contexts | Header codec and version table tests |
| T89-H-002 | PROJECT MUST | NOT_STARTED | Support Authentication, Authorization, and Accounting packet types | Independent golden encode/decode fixtures for each request and reply body |
| T89-H-003 | MUST | NOT_STARTED | First packet sequence is 1; client packets are odd and server packets are even | State-machine positive and negative tests |
| T89-H-004 | MUST | NOT_STARTED | Sequence numbers never wrap | Boundary fixture at 255 and required session termination |
| T89-H-005 | MUST | NOT_STARTED | Unknown header options or unsupported defined options produce ERROR and terminate when packet type is known | Golden malformed cases for each packet type |
| T89-H-006 | MUST | NOT_STARTED | When packet type cannot be determined, return identical clear header with sequence incremented and zero body length as required | Independent raw fixture |
| T89-H-007 | MUST | NOT_STARTED | Ignore unknown flag bits when reading and set them to zero when writing | Unit/golden tests |
| T89-H-008 | MUST | NOT_STARTED | Session ID remains stable for the session; generated server-side IDs use cryptographic randomness where applicable | Unit test with injectable randomness |
| T89-H-009 | MUST | NOT_STARTED | Maximum accepted body size is configurable; default/recommended budget is 65536 bytes | Limit tests before allocation and memory benchmark |
| T89-H-010 | MUST | NOT_STARTED | Sum of decoded body component lengths exactly matches header body length | Mismatch fixtures and fuzz assertion |
| T89-H-011 | MUST | NOT_STARTED | Bounded short-read handling for header and body | Fragmented reader tests and fuzz corpus |
| T89-H-012 | MUST | NOT_STARTED | Username text follows the required UsernameCasePreserved profile | Normalization and invalid-input cases |
| T89-H-013 | MUST | NOT_STARTED | Other text fields reject non-printable control characters where RFC requires printable US-ASCII | Field-specific tests |
| T89-H-014 | MUST | NOT_STARTED | Arbitrary-byte data fields are not incorrectly treated as printable text | CHAP/MS-CHAP fixtures |
| T89-H-015 | MUST | NOT_STARTED | A variable-length field whose encoded length is zero is ignored and treated as absent | Zero-length fixtures for every packet family |
| T89-H-016 | PROJECT | NOT_STARTED | All length arithmetic is overflow-safe before slicing or allocating | Boundary, fuzz, and memory-limit tests |
| T89-L-001 | MUST | NOT_STARTED | Accept connections only from configured known clients | Unknown-IP integration test |
| T89-L-002 | MUST | NOT_STARTED | Allow a unique shared secret per client | Two clients with distinct secrets and cross-secret failure tests |
| T89-L-003 | MUST | NOT_STARTED | Apply RFC 8907 packet-body obfuscation with flag clear | Independent known-answer vectors for multiple body lengths |
| T89-L-004 | MUST NOT | NOT_STARTED | Do not accept legacy packets with TAC_PLUS_UNENCRYPTED_FLAG set | Raw cleartext fixture is dropped/rejected |
| T89-L-005 | MUST | NOT_STARTED | Invalid shared secret or invalid decoded component lengths returns ERROR when possible | Wrong-secret fixtures for authen/author/acct |
| T89-L-006 | MUST | NOT_STARTED | After a connection-level secret error, accept no new sessions and close after existing valid sessions complete | Multiplexed integration test |
| T89-L-007 | MUST | NOT_STARTED | Shared-secret values are never logged or returned | Secret canary scanning tests |
| T89-L-008 | PROJECT MUST | NOT_STARTED | IPv4 and IPv6 configured client matching | Integration tests on both families where CI supports IPv6 |
| T89-L-009 | PROJECT | NOT_STARTED | Longest-prefix then priority selection is deterministic; unresolved ties reject config | State compiler table tests |
| T89-SC-001 | MUST | NOT_STARTED | Negotiate single-connect only through the first request/reply flag exchange | Positive and invalid late-flag tests |
| T89-SC-002 | MUST | NOT_STARTED | Client cannot send a second packet before negotiation is established | Connection-state negative test |
| T89-SC-003 | MUST | NOT_STARTED | If single-connect is not established, close after the first session | Integration test |
| T89-SC-004 | MAY | NOT_STARTED | Server may refuse single-connect per client configuration | Config and interop test |
| T89-SC-005 | PROJECT MUST | NOT_STARTED | Multiplex sessions by session ID on one connection | Concurrent authen/author/acct test |
| T89-SC-006 | PROJECT MUST | NOT_STARTED | Preserve packet order within one session while allowing concurrency across sessions | Race test and stress test |
| T89-SC-007 | MUST | NOT_STARTED | Idle timeout is configurable and closes inactive single-connect connections | Fake-clock or bounded integration test |
| T89-SC-008 | PROJECT MUST | NOT_STARTED | Connection closure does not leak session goroutines or block server shutdown | Leak/race tests |
| T89-SC-009 | PROJECT | NOT_STARTED | Per-connection session cap and fair write serialization prevent resource starvation | Load and adversarial tests |
| T89-ACT-001 | PROJECT MUST | NOT_STARTED | TAC_PLUS_AUTHEN_LOGIN | Implement all defined login types |
| T89-ACT-002 | PROJECT MUST | NOT_STARTED | TAC_PLUS_AUTHEN_CHPASS | Implement ASCII password change |
| T89-ACT-003 | SHOULD NOT | NOT_STARTED | TAC_PLUS_AUTHEN_SENDAUTH | Disabled by default and explicitly rejected; never silently accepted |
| T89-ACT-004 | Removed | NOT_STARTED | SENDPASS | Do not implement or advertise; explicit unknown/unsupported behavior tested |
| T89-TYPE-001 | PROJECT MUST | NOT_STARTED | ASCII 0x01 | Multi-step username/password flow |
| T89-TYPE-002 | PROJECT MUST | NOT_STARTED | PAP 0x02 | One START, one final REPLY |
| T89-TYPE-003 | PROJECT MUST | NOT_STARTED | CHAP 0x03 | Verify PPP ID/challenge/16-byte response format and MD5 response |
| T89-TYPE-004 | PROJECT MUST | NOT_STARTED | MS-CHAP v1 0x05 | Verify exact packet lengths, 8-byte challenge, and algorithm vectors |
| T89-TYPE-005 | PROJECT MUST | NOT_STARTED | MS-CHAP v2 0x06 | Verify exact packet lengths, 16-byte challenge, and algorithm vectors |
| T89-TYPE-006 | PROJECT MUST | NOT_STARTED | NOT_SET in authorization/accounting only | Accept only in allowed packet contexts |
| T89-TYPE-007 | PROJECT MUST | NOT_STARTED | Unknown type | Return the required failure/error and terminate/restart correctly |
| T89-SVC-001 | PROJECT MUST | NOT_STARTED | NONE 0x00 | Valid in documented authorization context; reject invalid auth flow usage |
| T89-SVC-002 | PROJECT MUST | NOT_STARTED | LOGIN 0x01 | Normal device login |
| T89-SVC-003 | PROJECT MUST | NOT_STARTED | ENABLE 0x02 | Privilege elevation flow |
| T89-SVC-004 | PROJECT MUST | NOT_STARTED | PPP 0x03 | Parse, expose to policy, and support valid defined auth types |
| T89-SVC-005 | PROJECT MUST | NOT_STARTED | PT 0x05 | Parse, expose, and permit explicit policy |
| T89-SVC-006 | PROJECT MUST | NOT_STARTED | RCMD 0x06 | Parse, expose, and permit explicit policy |
| T89-SVC-007 | PROJECT MUST | NOT_STARTED | X25 0x07 | Parse, expose, and permit explicit policy |
| T89-SVC-008 | PROJECT MUST | NOT_STARTED | NASI 0x08 | Parse, expose, and permit explicit policy |
| T89-SVC-009 | PROJECT MUST | NOT_STARTED | FWPROXY 0x09 | Parse, expose, and permit explicit policy |
| T89-SVC-010 | PROJECT MUST | NOT_STARTED | Unknown | Reject with correct status rather than ignoring |
| T89-AS-001 | MUST | NOT_STARTED | PASS terminates successfully | Flow tests |
| T89-AS-002 | MUST | NOT_STARTED | FAIL terminates as authentication denial | Flow tests |
| T89-AS-003 | MUST | NOT_STARTED | GETDATA continues and prompts for generic data | Multi-step fixture |
| T89-AS-004 | MUST | NOT_STARTED | GETUSER continues and obtains username | Missing-username ASCII fixture |
| T89-AS-005 | MUST | NOT_STARTED | GETPASS continues and uses NOECHO for secrets | UI/protocol fixture |
| T89-AS-006 | MUST | NOT_STARTED | RESTART ends current session and allows client to start a new session ID/type | Integration fixture |
| T89-AS-007 | MUST | NOT_STARTED | ERROR is distinct from FAIL and triggers unavailable-server handling semantics | Protocol integration |
| T89-AS-008 | Deprecated | NOT_STARTED | FOLLOW is not emitted; received/legacy behavior is safely failed | Negative fixture |
| T89-AS-009 | MUST | NOT_STARTED | Continue ABORT terminates the authentication session and safely records reason | Multi-step abort fixture |
| T89-AS-010 | MUST | NOT_STARTED | Retry count is bounded; recommended default three | Config and boundary tests |
| T89-AS-011 | MUST | NOT_STARTED | A defined authentication option not implemented by a selected profile returns TAC_PLUS_AUTHEN_STATUS_FAIL | Per-option disabled-profile fixtures |
| T89-AS-012 | SHOULD | NOT_STARTED | GETDATA/GETUSER/GETPASS replies include usable prompt text | Golden prompt fixtures |
| T89-AS-013 | SHOULD/MUST | NOT_STARTED | Sensitive prompts set NOECHO and never reflect submitted secret material | Protocol, UI, and secret-canary tests |
| T89-FLOW-001 | PROJECT MUST | NOT_STARTED | ASCII LOGIN with username in START | version=0; positive=PASS; negative=wrong password, disabled user |
| T89-FLOW-002 | PROJECT MUST | NOT_STARTED | ASCII LOGIN with GETUSER then GETPASS | version=0; positive=PASS; negative=empty/retry exhaustion/abort |
| T89-FLOW-003 | PROJECT MUST | NOT_STARTED | PAP LOGIN | version=1; positive=PASS; negative=wrong version, missing user/data, wrong password |
| T89-FLOW-004 | PROJECT MUST | NOT_STARTED | CHAP LOGIN | version=1; positive=independent response vector; negative=malformed ID/challenge/response, wrong secret |
| T89-FLOW-005 | PROJECT MUST | NOT_STARTED | MS-CHAP v1 LOGIN | version=1; positive=independent vector; negative=challenge length, response length, wrong secret |
| T89-FLOW-006 | PROJECT MUST | NOT_STARTED | MS-CHAP v2 LOGIN | version=1; positive=independent vector; negative=16-byte challenge enforcement, wrong secret |
| T89-FLOW-007 | PROJECT MUST | NOT_STARTED | ENABLE | version=0; positive=target privilege granted; negative=wrong credential, invalid service, disallowed target |
| T89-FLOW-008 | PROJECT MUST | NOT_STARTED | ASCII CHPASS | version=0; positive=runtime verifier override; negative=wrong old password, mismatch, immutable policy, abort |
| T89-FLOW-009 | PROJECT MUST | NOT_STARTED | Unsupported defined option | version=per RFC; positive=clean fail/error; negative=no panic, no state leak |
| T89-FLOW-010 | PROJECT MUST | NOT_STARTED | ASCII CHPASS old/new prompt semantics | version=0; positive=old password uses GETDATA; new password uses GETPASS; negative=reversed status, secret echo, interrupted update |
| T89-FLOW-011 | PROJECT MUST | NOT_STARTED | ASCII unused data fields | version=0; positive=arbitrary data is ignored as specified; negative=data cannot alter username/password decision |
| T89-FLOW-012 | PROJECT MUST | NOT_STARTED | CHAP challenge policy | version=1; positive=configurable minimum with recommended default of 8 bytes; negative=below-minimum and oversized challenge |
| T89-AU-001 | MUST | NOT_STARTED | Decode all request fields and preserve user, port, remote address, auth context, and ordered arguments | Golden fixture |
| T89-AU-002 | MUST NOT | NOT_STARTED | Do not trust authen_method for policy evaluation | Policy negative test |
| T89-AU-003 | MUST | NOT_STARTED | Recognize all authen-method codes for parsing/events | Enum table tests |
| T89-AU-004 | MUST | NOT_STARTED | Parse mandatory = and optional * separators at the first separator only | AV-pair unit/fuzz tests |
| T89-AU-005 | MUST | NOT_STARTED | Preserve duplicate and ordered AV pairs | Golden round-trip |
| T89-AU-006 | MUST | NOT_STARTED | Enforce AV-pair encoded length 2 through 255 bytes | Boundary tests |
| T89-AU-007 | MUST | NOT_STARTED | PASS_ADD with zero response args approves without modification | Independent client test |
| T89-AU-008 | MUST | NOT_STARTED | PASS_ADD appends/applies returned arguments correctly | Interop fixture |
| T89-AU-009 | MUST | NOT_STARTED | PASS_REPL replaces request arguments with response arguments | Interop fixture |
| T89-AU-010 | MUST | NOT_STARTED | FAIL denies the request | Tests |
| T89-AU-011 | MUST | NOT_STARTED | ERROR signals server processing failure, not policy denial | Tests |
| T89-AU-012 | Deprecated | NOT_STARTED | FOLLOW is not emitted | Tests |
| T89-AU-013 | MUST | NOT_STARTED | Unknown mandatory response arguments are never generated accidentally | Schema/policy validation |
| T89-AU-014 | PROJECT MUST | NOT_STARTED | Arbitrary vendor AV pairs can be matched, preserved, and returned | Vendor fixture |
| T89-AU-015 | PROJECT | NOT_STARTED | Default deny when no deterministic rule matches | Policy tests |
| T89-AU-016 | PROJECT | NOT_STARTED | Full explanation trace is stable and redacted | Golden trace tests |
| T89-AU-017 | SHOULD/PROJECT MUST | NOT_STARTED | Support the complete RFC 8907 common authorization argument dictionary | Dictionary table and vendor-neutral fixtures |
| T89-AU-018 | MUST | NOT_STARTED | Numeric argument lengths are checked before conversion; unrepresentable values are handled as unsupported arguments | Oversized and overflow fixtures |
| T89-AU-019 | MUST | NOT_STARTED | Absolute times use UTC unless an explicit timezone argument is present | Timezone fixtures with injected clock |
| T89-AU-020 | PROJECT MUST | NOT_STARTED | Validate/preserve the required primary service argument for supported use cases | Missing, empty, custom, and standard service cases |
| T89-AU-021 | PROJECT MUST | NOT_STARTED | Shell command authorization preserves and validates cmd plus ordered cmd-arg values | Session versus command fixtures |
| T89-AV-001 | PROJECT MUST | NOT_STARTED | service | Required primary service, including shell/system/firewall and custom strings |
| T89-AV-002 | PROJECT MUST | NOT_STARTED | protocol | Optional service subset |
| T89-AV-003 | PROJECT MUST | NOT_STARTED | cmd | Empty for session authorization; non-empty for command authorization |
| T89-AV-004 | PROJECT MUST | NOT_STARTED | cmd-arg | Ordered, repeatable command arguments |
| T89-AV-005 | PROJECT MUST | NOT_STARTED | acl | Numeric connection ACL |
| T89-AV-006 | PROJECT MUST | NOT_STARTED | inacl | Input ACL identifier |
| T89-AV-007 | PROJECT MUST | NOT_STARTED | outacl | Output ACL identifier |
| T89-AV-008 | PROJECT MUST | NOT_STARTED | addr | IPv4/IPv6 network address |
| T89-AV-009 | PROJECT MUST | NOT_STARTED | addr-pool | Address-pool identifier |
| T89-AV-010 | PROJECT MUST | NOT_STARTED | timeout | Absolute connection timeout in minutes |
| T89-AV-011 | PROJECT MUST | NOT_STARTED | idletime | Idle timeout in minutes |
| T89-AV-012 | PROJECT MUST | NOT_STARTED | autocmd | Session auto-command |
| T89-AV-013 | PROJECT MUST | NOT_STARTED | noescape | Boolean |
| T89-AV-014 | PROJECT MUST | NOT_STARTED | nohangup | Boolean |
| T89-AV-015 | PROJECT MUST | NOT_STARTED | priv-lvl | Numeric 0 through 15 |
| T89-AV-016 | PROJECT MUST | NOT_STARTED | vendor/unknown | Preserve arbitrary name/value/separator/order |
| T89-PRIV-001 | MUST | NOT_STARTED | Accept and preserve levels 0 through 15 |  |
| T89-PRIV-002 | MUST | NOT_STARTED | Reject values outside the encoded field/rule range |  |
| T89-PRIV-003 | SHOULD | NOT_STARTED | Support session-based shell authorization returning priv-lvl |  |
| T89-PRIV-004 | MUST | NOT_STARTED | ENABLE flow can request a higher privilege without assuming prior auth by protocol |  |
| T89-PRIV-005 | PROJECT | NOT_STARTED | Policy does not assume vendor command mappings for a privilege level |  |
| T89-AC-001 | MUST | NOT_STARTED | START flag only (0x02) | Golden/integration |
| T89-AC-002 | MUST | NOT_STARTED | STOP flag only (0x04) | Golden/integration |
| T89-AC-003 | MUST | NOT_STARTED | WATCHDOG no update (0x08), arguments ignored as required | Golden/integration |
| T89-AC-004 | MUST | NOT_STARTED | WATCHDOG with update (0x0a) | Golden/integration |
| T89-AC-005 | MUST | NOT_STARTED | Reject no flags, START+STOP, WATCHDOG+STOP, and other invalid combinations with ERROR | Full table test |
| T89-AC-006 | MUST | NOT_STARTED | Return SUCCESS only after the record is accepted by the authoritative sink | Fault injection |
| T89-AC-007 | MUST | NOT_STARTED | Return ERROR when the record cannot be accepted | Fault injection |
| T89-AC-008 | Deprecated | NOT_STARTED | FOLLOW is not emitted | Negative test |
| T89-AC-009 | MUST | NOT_STARTED | Preserve authentication/authorization context and ordered AV pairs | Golden fixture |
| T89-AC-010 | PROJECT MUST | NOT_STARTED | Command accounting supports service, cmd, and ordered cmd-arg | Interop fixture |
| T89-AC-011 | PROJECT | NOT_STARTED | Ring overwrite is bounded, observable, and does not block current acknowledgement | Load test |
| T89-AC-012 | MUST | NOT_STARTED | task_id is treated as opaque; the server makes no format assumptions | Arbitrary printable task ID fixtures |
| T89-AC-013 | PROJECT MUST | NOT_STARTED | Accounting-only arguments and following authorization arguments retain wire order | Golden ordering fixtures |
| T89-AC-014 | SHOULD/PROJECT MUST | NOT_STARTED | Common accounting string, numeric, Boolean, address, and time representations are accepted and displayed consistently | Dictionary/value encoding suite |
| T89-ACAV-001 | PROJECT MUST | NOT_STARTED | task_id | Opaque, correlated without format assumptions |
| T89-ACAV-002 | PROJECT MUST | NOT_STARTED | start_time | Epoch seconds |
| T89-ACAV-003 | PROJECT MUST | NOT_STARTED | stop_time | Epoch seconds |
| T89-ACAV-004 | PROJECT MUST | NOT_STARTED | elapsed_time | Seconds |
| T89-ACAV-005 | PROJECT MUST | NOT_STARTED | timezone | Applied to packet timestamps when present |
| T89-ACAV-006 | PROJECT MUST | NOT_STARTED | event | Standard system event values plus extensibility |
| T89-ACAV-007 | PROJECT MUST | NOT_STARTED | reason | Event reason |
| T89-ACAV-008 | PROJECT MUST | NOT_STARTED | bytes | Numeric |
| T89-ACAV-009 | PROJECT MUST | NOT_STARTED | bytes_in | Numeric |
| T89-ACAV-010 | PROJECT MUST | NOT_STARTED | bytes_out | Numeric |
| T89-ACAV-011 | PROJECT MUST | NOT_STARTED | paks | Numeric |
| T89-ACAV-012 | PROJECT MUST | NOT_STARTED | paks_in | Numeric |
| T89-ACAV-013 | PROJECT MUST | NOT_STARTED | paks_out | Numeric |
| T89-ACAV-014 | PROJECT MUST | NOT_STARTED | err_msg | Printable status text |
| T89-ACAV-015 | PROJECT MUST | NOT_STARTED | authorization args | Follow accounting-only arguments while preserving wire order |
| T89-ACAV-016 | PROJECT MUST | NOT_STARTED | vendor/unknown | Preserve arbitrary AV pairs |
| T89-SEC-001 | MUST | NOT_STARTED | Administrator can restrict authentication to challenge-response types |  |
| T89-SEC-002 | SHOULD | NOT_STARTED | Warn when ASCII/PAP are enabled and document that non-challenge methods should be enabled only when required |  |
| T89-SEC-003 | SHOULD NOT | NOT_STARTED | Avoid reusing the same credential across challenge and non-challenge types |  |
| T89-SEC-004 | SHOULD NOT | NOT_STARTED | SENDAUTH/SENDPASS are not implemented; any future implementation is disabled by default with a warning |  |
| T89-SEC-005 | MUST | NOT_STARTED | Redirection/FOLLOW is deprecated, not advertised, and disabled |  |
| T89-SEC-006 | MUST | NOT_STARTED | A dedicated legacy shared secret can be configured for each individual client |  |
| T89-SEC-007 | MUST/PROJECT MUST | NOT_STARTED | Every enabled legacy client has a shared secret and cleartext legacy packet bodies are rejected |  |
| T89-SEC-008 | PROJECT | NOT_STARTED | Operator UI clearly labels legacy transport as compatibility/insecure |  |
| T89-SEC-009 | MUST | NOT_STARTED | Shared secrets are treated as sensitive and never leaked, logged, exported, traced, or returned |  |
| T89-SEC-010 | MUST | NOT_STARTED | Shared keys of at least 32 characters are supported without truncation |  |
| T89-SEC-011 | MUST | NOT_STARTED | Configuration supports an enforceable minimum-complexity policy for legacy shared keys |  |
| T89-SEC-012 | MUST | NOT_STARTED | Management metadata can track shared-key lifetime and notify operators that rotation is due |  |
| T89-SEC-013 | SHOULD | NOT_STARTED | Validation warns when process-local keyed HMAC comparison detects that multiple clients reuse the same shared secret; no comparison value is exposed or persisted |  |
| T89-SEC-014 | OPERATOR SHOULD | NOT_STARTED | Generated/operator-provided legacy keys are at least 16 characters and rotated regularly |  |
| T89-SEC-015 | OPERATOR MUST | NOT_STARTED | Legacy TACACS is documented for a protected, integrity-preserving management network; operators are warned not to rely on obfuscation |  |
| T89-SEC-016 | PROJECT | NOT_STARTED | Configuration and deployment make secure TACACS+ the recommended mode for new lab topologies |  |

## RFC 9887

RFC 9887 Secure TACACS+

| ID | Level | Status | Requirement | Required evidence |
|---|---|---|---|---|
| T98-TLS-001 | MUST | NOT_STARTED | Secure TACACS+ listens on a port distinct from legacy | Config/startup tests |
| T98-TLS-002 | PROJECT MUST | NOT_STARTED | Support the well-known secure TACACS+ TCP port 300 through the reference deployment mapping | Compose test |
| T98-TLS-003 | MUST | NOT_STARTED | Begin TLS handshake immediately; no plaintext preface or upgrade | Raw socket negative test |
| T98-TLS-004 | MUST | NOT_STARTED | Minimum TLS version 1.3; TLS 1.2 and earlier rejected | TLS matrix test |
| T98-TLS-005 | MUST | NOT_STARTED | Encrypt all TACACS+ data as TLS application data | Packet capture/integration assertion |
| T98-TLS-006 | MUST | NOT_STARTED | Do not apply legacy TACACS+ obfuscation over TLS | Known packet/body test |
| T98-TLS-007 | MUST | NOT_STARTED | Non-single-connect TLS connection closes after session completion | Integration |
| T98-TLS-008 | MAY | NOT_STARTED | Single-connect TLS sessions persist until idle/other closure | Integration |
| T98-TLS-009 | PROJECT MUST | NOT_STARTED | IPv4 and IPv6 supported equivalently | Integration where available |
| T98-TLS-010 | MUST NOT | NOT_STARTED | The secure TACACS+ listener never accepts a non-TLS TACACS connection | Plaintext and protocol-sniffing negative tests |
| T98-TLS-011 | MUST | NOT_STARTED | TLS versions and algorithms follow BCP 195 and the TLS 1.3 mandatory implementation requirements | TLS configuration review and handshake matrix |
| T98-TLS-012 | SHOULD | NOT_STARTED | Configuration can require TLS globally and per client without ambiguous automatic fallback | Config compile and connection tests |
| T98-TLS-013 | NOT RECOMMENDED | NOT_STARTED | Co-locating secure and legacy listeners on one host follows [ADR 0001](decisions/0001-all-in-one-dual-listener-lab.md) and presents a production warning | ADR and deployment docs |
| T98-TLS-014 | SHOULD/PROJECT | NOT_STARTED | New deployment examples prefer TLS; legacy mode is clearly marked compatibility-only | Example config, UI, and operator docs |
| T98-TLS-015 | PROJECT MUST | NOT_STARTED | Default/reference port behavior is unambiguous: 49 legacy and 300 secure, with explicit override support | Config and Compose tests |
| T98-CERT-001 | MUST | NOT_STARTED | Support certificate-based mutual authentication | Positive mTLS test |
| T98-CERT-002 | MUST | NOT_STARTED | Validate remote certificate path | Unknown CA/expired/not-yet-valid tests |
| T98-CERT-003 | MUST | NOT_STARTED | Support configured certificate chains/bundles | Intermediate chain test |
| T98-CERT-004 | MUST/Policy | NOT_STARTED | Invalid certificate is denied by default | Negative matrix |
| T98-CERT-005 | MUST | NOT_STARTED | Server maps client certificate identity using supported network-address or SAN identity method | DNS SAN and IP SAN cases |
| T98-CERT-006 | MUST | NOT_STARTED | Support SNI | Multiple certificate profile test |
| T98-CERT-007 | MUST | NOT_STARTED | Support TLS 1.3 mandatory cipher suites offered by the Go TLS stack | Handshake matrix |
| T98-CERT-008 | SHOULD | NOT_STARTED | Cipher policy is configurable within safe supported options | Config test |
| T98-CERT-009 | MUST | NOT_STARTED | Revocation policy is implemented and documented | Revoked-cert test or approved mechanism-specific evidence |
| T98-CERT-010 | SHOULD | NOT_STARTED | TLS cached-information extension disposition documented | Implementation or ADR |
| T98-CERT-011 | MUST | NOT_STARTED | Client certificate identification fields are configurable; dNSName and iPAddress SAN matching are supported | Exact DNS/IP SAN and source-address tests |
| T98-CERT-012 | OPERATOR MUST/SHOULD | NOT_STARTED | Wildcard server identities follow RFC 9525 restrictions and are limited to a TACACS-only subdomain when used | Certificate validation warning and deployment evidence |
| T98-CERT-013 | PROJECT | NOT_STARTED | The baseline profile cannot silently disable certificate validation or mutual authentication | Config-negative and startup tests |
| T98-CERT-014 | MUST | NOT_STARTED | Revocation checking applies to the selected certificate path mechanism and fails according to documented policy | CRL/OCSP or approved mechanism tests |
| T98-FLAG-001 | MUST | NOT_STARTED | Every TACACS packet over TLS has TAC_PLUS_UNENCRYPTED_FLAG set to 1 | Golden/integration |
| T98-FLAG-002 | MUST | NOT_STARTED | Packet received over TLS without flag set returns type-specific ERROR with flag set and terminates session | Authen/author/acct raw fixtures |
| T98-FLAG-003 | MUST | NOT_STARTED | Legacy shared-secret obfuscation keys are not used as TLS peer authentication | Config/type tests |
| T98-RES-001 | SHOULD | NOT_STARTED | Client/server resumption behavior is supported or dispositioned | Integration or ADR |
| T98-RES-002 | SHOULD | NOT_STARTED | Ticket lifetime is configurable, including zero | Config/handshake test |
| T98-RES-003 | MUST NOT | NOT_STARTED | Accept or send 0-RTT TACACS+ data | Early-data negative test or stack capability evidence |
| T98-RES-004 | MUST NOT | NOT_STARTED | Include the TLS early_data extension | Handshake inspection |
| T98-RES-005 | MUST/SHOULD | NOT_STARTED | Certificate revocation implications during resumption are handled and documented | Security test/ADR |
| T98-RES-006 | SHOULD | NOT_STARTED | Server permits valid, unexpired, unused resumption tickets or records a stack limitation/ADR | Handshake integration or ADR |
| T98-RES-007 | SHOULD | NOT_STARTED | Ticket reuse/linkability and TLS 1.3 client-tracking mitigations are reviewed and dispositioned | Security test/ADR |
| T98-RES-008 | PROJECT | NOT_STARTED | Resumption can be disabled for strict lab scenarios without changing normal full-handshake behavior | Config and handshake tests |
| T98-OPT-001 | MAY | NOT_STARTED | External TLS 1.3 PSK | Implement behind an isolated authentication adapter or record DEFERRED_MAY; do not advertise otherwise |
| T98-OPT-002 | MUST if PSK implemented | NOT_STARTED | Support PSKs of at least 16 octets and identities of at least 16 octets | Boundary and interoperability tests |
| T98-OPT-003 | MUST NOT if PSK implemented | NOT_STARTED | Never reuse a legacy TACACS obfuscation shared secret as a TLS PSK | Typed-secret and canary tests |
| T98-OPT-004 | RECOMMENDED if PSK implemented | NOT_STARTED | Follow RFC 9257 external-PSK guidance | Security review and ADR |
| T98-OPT-005 | MAY/out of detailed scope | NOT_STARTED | Raw Public Keys | Implement behind an isolated adapter or record DEFERRED_MAY |
| T98-ROLE-001 | CLIENT-ROLE MUST | NOT_STARTED | Test client begins TLS immediately and sends no TACACS data before handshake completion | Independent client integration |
| T98-ROLE-002 | CLIENT-ROLE MUST NOT | NOT_STARTED | Test client never falls back to legacy after a TLS failure | Downgrade negative test |
| T98-ROLE-003 | CLIENT-ROLE MUST | NOT_STARTED | Test client validates server identity using RFC 9525-supported DNS-ID/IP-ID/SRV-ID behavior; URI-ID is not used for server identity | Certificate-name matrix |
| T98-ROLE-004 | CLIENT-ROLE MUST | NOT_STARTED | Test client sends the unencrypted flag on every packet over TLS and terminates on a nonconforming server reply | Raw peer fixtures |
| T98-ROLE-005 | CLIENT-ROLE MUST NOT | NOT_STARTED | Test client sends no 0-RTT and includes no early-data extension | Handshake inspection |
| T98-ROLE-006 | OPERATOR SHOULD | NOT_STARTED | Production-like security tests run TLS-only or use separate hosts/instances for legacy and secure services | Lab topology evidence |

