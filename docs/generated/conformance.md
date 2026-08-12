# Generated TACACS+ conformance inventory

Do not hand-edit this file. Run `make generate`.

Sources: `testdata/conformance/rfc8907.yaml`, `testdata/conformance/rfc9887.yaml`

Status columns start `NOT_STARTED` with empty evidence.

## RFC 8907

RFC 8907 TACACS+

| ID | Level | Status | Requirement |
|---|---|---|---|
| T89-H-001 | PROJECT MUST | NOT_STARTED | Support TACACS+ major version 0xc and minor versions 0 and 1 in their valid contexts |
| T89-H-002 | PROJECT MUST | NOT_STARTED | Support Authentication, Authorization, and Accounting packet types |
| T89-H-003 | MUST | NOT_STARTED | First packet sequence is 1; client packets are odd and server packets are even |
| T89-H-004 | MUST | NOT_STARTED | Sequence numbers never wrap |
| T89-H-005 | MUST | NOT_STARTED | Unknown header options or unsupported defined options produce ERROR and terminate when packet type is known |
| T89-H-006 | MUST | NOT_STARTED | When packet type cannot be determined, return identical clear header with sequence incremented and zero body length as required |
| T89-H-007 | MUST | NOT_STARTED | Ignore unknown flag bits when reading and set them to zero when writing |
| T89-H-008 | MUST | NOT_STARTED | Session ID remains stable for the session; generated server-side IDs use cryptographic randomness where applicable |
| T89-H-009 | MUST | NOT_STARTED | Maximum accepted body size is configurable; default/recommended budget is 65536 bytes |
| T89-H-010 | MUST | NOT_STARTED | Sum of decoded body component lengths exactly matches header body length |
| T89-H-011 | MUST | NOT_STARTED | Bounded short-read handling for header and body |
| T89-H-012 | MUST | NOT_STARTED | Username text follows the required UsernameCasePreserved profile |
| T89-H-013 | MUST | NOT_STARTED | Other text fields reject non-printable control characters where RFC requires printable US-ASCII |
| T89-H-014 | MUST | NOT_STARTED | Arbitrary-byte data fields are not incorrectly treated as printable text |
| T89-H-015 | MUST | NOT_STARTED | A variable-length field whose encoded length is zero is ignored and treated as absent |
| T89-H-016 | PROJECT | NOT_STARTED | All length arithmetic is overflow-safe before slicing or allocating |
| T89-L-001 | MUST | NOT_STARTED | Accept connections only from configured known clients |
| T89-L-002 | MUST | NOT_STARTED | Allow a unique shared secret per client |
| T89-L-003 | MUST | NOT_STARTED | Apply RFC 8907 packet-body obfuscation with flag clear |
| T89-L-004 | MUST NOT | NOT_STARTED | Do not accept legacy packets with TAC_PLUS_UNENCRYPTED_FLAG set |
| T89-L-005 | MUST | NOT_STARTED | Invalid shared secret or invalid decoded component lengths returns ERROR when possible |
| T89-L-006 | MUST | NOT_STARTED | After a connection-level secret error, accept no new sessions and close after existing valid sessions complete |
| T89-L-007 | MUST | NOT_STARTED | Shared-secret values are never logged or returned |
| T89-L-008 | PROJECT MUST | NOT_STARTED | IPv4 and IPv6 configured client matching |
| T89-L-009 | PROJECT | NOT_STARTED | Longest-prefix then priority selection is deterministic; unresolved ties reject config |
| T89-SC-001 | MUST | NOT_STARTED | Negotiate single-connect only through the first request/reply flag exchange |
| T89-SC-002 | MUST | NOT_STARTED | Client cannot send a second packet before negotiation is established |
| T89-SC-003 | MUST | NOT_STARTED | If single-connect is not established, close after the first session |
| T89-SC-004 | MAY | NOT_STARTED | Server may refuse single-connect per client configuration |
| T89-SC-005 | PROJECT MUST | NOT_STARTED | Multiplex sessions by session ID on one connection |
| T89-SC-006 | PROJECT MUST | NOT_STARTED | Preserve packet order within one session while allowing concurrency across sessions |
| T89-SC-007 | MUST | NOT_STARTED | Idle timeout is configurable and closes inactive single-connect connections |
| T89-SC-008 | PROJECT MUST | NOT_STARTED | Connection closure does not leak session goroutines or block server shutdown |
| T89-SC-009 | PROJECT | NOT_STARTED | Per-connection session cap and fair write serialization prevent resource starvation |
| T89-ACT-001 | PROJECT MUST | NOT_STARTED | TAC_PLUS_AUTHEN_LOGIN |
| T89-ACT-002 | PROJECT MUST | NOT_STARTED | TAC_PLUS_AUTHEN_CHPASS |
| T89-ACT-003 | SHOULD NOT | NOT_STARTED | TAC_PLUS_AUTHEN_SENDAUTH |
| T89-ACT-004 | Removed | NOT_STARTED | SENDPASS |
| T89-TYPE-001 | PROJECT MUST | NOT_STARTED | ASCII 0x01 |
| T89-TYPE-002 | PROJECT MUST | NOT_STARTED | PAP 0x02 |
| T89-TYPE-003 | PROJECT MUST | NOT_STARTED | CHAP 0x03 |
| T89-TYPE-004 | PROJECT MUST | NOT_STARTED | MS-CHAP v1 0x05 |
| T89-TYPE-005 | PROJECT MUST | NOT_STARTED | MS-CHAP v2 0x06 |
| T89-TYPE-006 | PROJECT MUST | NOT_STARTED | NOT_SET in authorization/accounting only |
| T89-TYPE-007 | PROJECT MUST | NOT_STARTED | Unknown type |
| T89-SVC-001 | PROJECT MUST | NOT_STARTED | NONE 0x00 |
| T89-SVC-002 | PROJECT MUST | NOT_STARTED | LOGIN 0x01 |
| T89-SVC-003 | PROJECT MUST | NOT_STARTED | ENABLE 0x02 |
| T89-SVC-004 | PROJECT MUST | NOT_STARTED | PPP 0x03 |
| T89-SVC-005 | PROJECT MUST | NOT_STARTED | PT 0x05 |
| T89-SVC-006 | PROJECT MUST | NOT_STARTED | RCMD 0x06 |
| T89-SVC-007 | PROJECT MUST | NOT_STARTED | X25 0x07 |
| T89-SVC-008 | PROJECT MUST | NOT_STARTED | NASI 0x08 |
| T89-SVC-009 | PROJECT MUST | NOT_STARTED | FWPROXY 0x09 |
| T89-SVC-010 | PROJECT MUST | NOT_STARTED | Unknown |
| T89-AS-001 | MUST | NOT_STARTED | PASS terminates successfully |
| T89-AS-002 | MUST | NOT_STARTED | FAIL terminates as authentication denial |
| T89-AS-003 | MUST | NOT_STARTED | GETDATA continues and prompts for generic data |
| T89-AS-004 | MUST | NOT_STARTED | GETUSER continues and obtains username |
| T89-AS-005 | MUST | NOT_STARTED | GETPASS continues and uses NOECHO for secrets |
| T89-AS-006 | MUST | NOT_STARTED | RESTART ends current session and allows client to start a new session ID/type |
| T89-AS-007 | MUST | NOT_STARTED | ERROR is distinct from FAIL and triggers unavailable-server handling semantics |
| T89-AS-008 | Deprecated | NOT_STARTED | FOLLOW is not emitted; received/legacy behavior is safely failed |
| T89-AS-009 | MUST | NOT_STARTED | Continue ABORT terminates the authentication session and safely records reason |
| T89-AS-010 | MUST | NOT_STARTED | Retry count is bounded; recommended default three |
| T89-AS-011 | MUST | NOT_STARTED | A defined authentication option not implemented by a selected profile returns TAC_PLUS_AUTHEN_STATUS_FAIL |
| T89-AS-012 | SHOULD | NOT_STARTED | GETDATA/GETUSER/GETPASS replies include usable prompt text |
| T89-AS-013 | SHOULD/MUST | NOT_STARTED | Sensitive prompts set NOECHO and never reflect submitted secret material |
| T89-FLOW-001 | PROJECT MUST | NOT_STARTED | ASCII LOGIN with username in START |
| T89-FLOW-002 | PROJECT MUST | NOT_STARTED | ASCII LOGIN with GETUSER then GETPASS |
| T89-FLOW-003 | PROJECT MUST | NOT_STARTED | PAP LOGIN |
| T89-FLOW-004 | PROJECT MUST | NOT_STARTED | CHAP LOGIN |
| T89-FLOW-005 | PROJECT MUST | NOT_STARTED | MS-CHAP v1 LOGIN |
| T89-FLOW-006 | PROJECT MUST | NOT_STARTED | MS-CHAP v2 LOGIN |
| T89-FLOW-007 | PROJECT MUST | NOT_STARTED | ENABLE |
| T89-FLOW-008 | PROJECT MUST | NOT_STARTED | ASCII CHPASS |
| T89-FLOW-009 | PROJECT MUST | NOT_STARTED | Unsupported defined option |
| T89-FLOW-010 | PROJECT MUST | NOT_STARTED | ASCII CHPASS old/new prompt semantics |
| T89-FLOW-011 | PROJECT MUST | NOT_STARTED | ASCII unused data fields |
| T89-FLOW-012 | PROJECT MUST | NOT_STARTED | CHAP challenge policy |
| T89-AU-001 | MUST | NOT_STARTED | Decode all request fields and preserve user, port, remote address, auth context, and ordered arguments |
| T89-AU-002 | MUST NOT | NOT_STARTED | Do not trust authen_method for policy evaluation |
| T89-AU-003 | MUST | NOT_STARTED | Recognize all authen-method codes for parsing/events |
| T89-AU-004 | MUST | NOT_STARTED | Parse mandatory = and optional * separators at the first separator only |
| T89-AU-005 | MUST | NOT_STARTED | Preserve duplicate and ordered AV pairs |
| T89-AU-006 | MUST | NOT_STARTED | Enforce AV-pair encoded length 2 through 255 bytes |
| T89-AU-007 | MUST | NOT_STARTED | PASS_ADD with zero response args approves without modification |
| T89-AU-008 | MUST | NOT_STARTED | PASS_ADD appends/applies returned arguments correctly |
| T89-AU-009 | MUST | NOT_STARTED | PASS_REPL replaces request arguments with response arguments |
| T89-AU-010 | MUST | NOT_STARTED | FAIL denies the request |
| T89-AU-011 | MUST | NOT_STARTED | ERROR signals server processing failure, not policy denial |
| T89-AU-012 | Deprecated | NOT_STARTED | FOLLOW is not emitted |
| T89-AU-013 | MUST | NOT_STARTED | Unknown mandatory response arguments are never generated accidentally |
| T89-AU-014 | PROJECT MUST | NOT_STARTED | Arbitrary vendor AV pairs can be matched, preserved, and returned |
| T89-AU-015 | PROJECT | NOT_STARTED | Default deny when no deterministic rule matches |
| T89-AU-016 | PROJECT | NOT_STARTED | Full explanation trace is stable and redacted |
| T89-AU-017 | SHOULD/PROJECT MUST | NOT_STARTED | Support the complete RFC 8907 common authorization argument dictionary |
| T89-AU-018 | MUST | NOT_STARTED | Numeric argument lengths are checked before conversion; unrepresentable values are handled as unsupported arguments |
| T89-AU-019 | MUST | NOT_STARTED | Absolute times use UTC unless an explicit timezone argument is present |
| T89-AU-020 | PROJECT MUST | NOT_STARTED | Validate/preserve the required primary service argument for supported use cases |
| T89-AU-021 | PROJECT MUST | NOT_STARTED | Shell command authorization preserves and validates cmd plus ordered cmd-arg values |
| T89-AV-001 | PROJECT MUST | NOT_STARTED | service |
| T89-AV-002 | PROJECT MUST | NOT_STARTED | protocol |
| T89-AV-003 | PROJECT MUST | NOT_STARTED | cmd |
| T89-AV-004 | PROJECT MUST | NOT_STARTED | cmd-arg |
| T89-AV-005 | PROJECT MUST | NOT_STARTED | acl |
| T89-AV-006 | PROJECT MUST | NOT_STARTED | inacl |
| T89-AV-007 | PROJECT MUST | NOT_STARTED | outacl |
| T89-AV-008 | PROJECT MUST | NOT_STARTED | addr |
| T89-AV-009 | PROJECT MUST | NOT_STARTED | addr-pool |
| T89-AV-010 | PROJECT MUST | NOT_STARTED | timeout |
| T89-AV-011 | PROJECT MUST | NOT_STARTED | idletime |
| T89-AV-012 | PROJECT MUST | NOT_STARTED | autocmd |
| T89-AV-013 | PROJECT MUST | NOT_STARTED | noescape |
| T89-AV-014 | PROJECT MUST | NOT_STARTED | nohangup |
| T89-AV-015 | PROJECT MUST | NOT_STARTED | priv-lvl |
| T89-AV-016 | PROJECT MUST | NOT_STARTED | vendor/unknown |
| T89-PRIV-001 | MUST | NOT_STARTED | Accept and preserve levels 0 through 15 |
| T89-PRIV-002 | MUST | NOT_STARTED | Reject values outside the encoded field/rule range |
| T89-PRIV-003 | SHOULD | NOT_STARTED | Support session-based shell authorization returning priv-lvl |
| T89-PRIV-004 | MUST | NOT_STARTED | ENABLE flow can request a higher privilege without assuming prior auth by protocol |
| T89-PRIV-005 | PROJECT | NOT_STARTED | Policy does not assume vendor command mappings for a privilege level |
| T89-AC-001 | MUST | NOT_STARTED | START flag only (0x02) |
| T89-AC-002 | MUST | NOT_STARTED | STOP flag only (0x04) |
| T89-AC-003 | MUST | NOT_STARTED | WATCHDOG no update (0x08), arguments ignored as required |
| T89-AC-004 | MUST | NOT_STARTED | WATCHDOG with update (0x0a) |
| T89-AC-005 | MUST | NOT_STARTED | Reject no flags, START+STOP, WATCHDOG+STOP, and other invalid combinations with ERROR |
| T89-AC-006 | MUST | NOT_STARTED | Return SUCCESS only after the record is accepted by the authoritative sink |
| T89-AC-007 | MUST | NOT_STARTED | Return ERROR when the record cannot be accepted |
| T89-AC-008 | Deprecated | NOT_STARTED | FOLLOW is not emitted |
| T89-AC-009 | MUST | NOT_STARTED | Preserve authentication/authorization context and ordered AV pairs |
| T89-AC-010 | PROJECT MUST | NOT_STARTED | Command accounting supports service, cmd, and ordered cmd-arg |
| T89-AC-011 | PROJECT | NOT_STARTED | Ring overwrite is bounded, observable, and does not block current acknowledgement |
| T89-AC-012 | MUST | NOT_STARTED | task_id is treated as opaque; the server makes no format assumptions |
| T89-AC-013 | PROJECT MUST | NOT_STARTED | Accounting-only arguments and following authorization arguments retain wire order |
| T89-AC-014 | SHOULD/PROJECT MUST | NOT_STARTED | Common accounting string, numeric, Boolean, address, and time representations are accepted and displayed consistently |
| T89-ACAV-001 | PROJECT MUST | NOT_STARTED | task_id |
| T89-ACAV-002 | PROJECT MUST | NOT_STARTED | start_time |
| T89-ACAV-003 | PROJECT MUST | NOT_STARTED | stop_time |
| T89-ACAV-004 | PROJECT MUST | NOT_STARTED | elapsed_time |
| T89-ACAV-005 | PROJECT MUST | NOT_STARTED | timezone |
| T89-ACAV-006 | PROJECT MUST | NOT_STARTED | event |
| T89-ACAV-007 | PROJECT MUST | NOT_STARTED | reason |
| T89-ACAV-008 | PROJECT MUST | NOT_STARTED | bytes |
| T89-ACAV-009 | PROJECT MUST | NOT_STARTED | bytes_in |
| T89-ACAV-010 | PROJECT MUST | NOT_STARTED | bytes_out |
| T89-ACAV-011 | PROJECT MUST | NOT_STARTED | paks |
| T89-ACAV-012 | PROJECT MUST | NOT_STARTED | paks_in |
| T89-ACAV-013 | PROJECT MUST | NOT_STARTED | paks_out |
| T89-ACAV-014 | PROJECT MUST | NOT_STARTED | err_msg |
| T89-ACAV-015 | PROJECT MUST | NOT_STARTED | authorization args |
| T89-ACAV-016 | PROJECT MUST | NOT_STARTED | vendor/unknown |
| T89-SEC-001 | MUST | NOT_STARTED | Administrator can restrict authentication to challenge-response types |
| T89-SEC-002 | SHOULD | NOT_STARTED | Warn when ASCII/PAP are enabled and document that non-challenge methods should be enabled only when required |
| T89-SEC-003 | SHOULD NOT | NOT_STARTED | Avoid reusing the same credential across challenge and non-challenge types |
| T89-SEC-004 | SHOULD NOT | NOT_STARTED | SENDAUTH/SENDPASS are not implemented; any future implementation is disabled by default with a warning |
| T89-SEC-005 | MUST | NOT_STARTED | Redirection/FOLLOW is deprecated, not advertised, and disabled |
| T89-SEC-006 | MUST | NOT_STARTED | A dedicated legacy shared secret can be configured for each individual client |
| T89-SEC-007 | MUST/PROJECT MUST | NOT_STARTED | Every enabled legacy client has a shared secret and cleartext legacy packet bodies are rejected |
| T89-SEC-008 | PROJECT | NOT_STARTED | Operator UI clearly labels legacy transport as compatibility/insecure |
| T89-SEC-009 | MUST | NOT_STARTED | Shared secrets are treated as sensitive and never leaked, logged, exported, traced, or returned |
| T89-SEC-010 | MUST | NOT_STARTED | Shared keys of at least 32 characters are supported without truncation |
| T89-SEC-011 | MUST | NOT_STARTED | Configuration supports an enforceable minimum-complexity policy for legacy shared keys |
| T89-SEC-012 | MUST | NOT_STARTED | Management metadata can track shared-key lifetime and notify operators that rotation is due |
| T89-SEC-013 | SHOULD | NOT_STARTED | Validation warns when process-local keyed HMAC comparison detects that multiple clients reuse the same shared secret; no comparison value is exposed or persisted |
| T89-SEC-014 | OPERATOR SHOULD | NOT_STARTED | Generated/operator-provided legacy keys are at least 16 characters and rotated regularly |
| T89-SEC-015 | OPERATOR MUST | NOT_STARTED | Legacy TACACS is documented for a protected, integrity-preserving management network; operators are warned not to rely on obfuscation |
| T89-SEC-016 | PROJECT | NOT_STARTED | Configuration and deployment make secure TACACS+ the recommended mode for new lab topologies |

## RFC 9887

RFC 9887 Secure TACACS+

| ID | Level | Status | Requirement |
|---|---|---|---|
| T98-TLS-001 | MUST | NOT_STARTED | Secure TACACS+ listens on a port distinct from legacy |
| T98-TLS-002 | PROJECT MUST | NOT_STARTED | Support the well-known secure TACACS+ TCP port 300 through the reference deployment mapping |
| T98-TLS-003 | MUST | NOT_STARTED | Begin TLS handshake immediately; no plaintext preface or upgrade |
| T98-TLS-004 | MUST | NOT_STARTED | Minimum TLS version 1.3; TLS 1.2 and earlier rejected |
| T98-TLS-005 | MUST | NOT_STARTED | Encrypt all TACACS+ data as TLS application data |
| T98-TLS-006 | MUST | NOT_STARTED | Do not apply legacy TACACS+ obfuscation over TLS |
| T98-TLS-007 | MUST | NOT_STARTED | Non-single-connect TLS connection closes after session completion |
| T98-TLS-008 | MAY | NOT_STARTED | Single-connect TLS sessions persist until idle/other closure |
| T98-TLS-009 | PROJECT MUST | NOT_STARTED | IPv4 and IPv6 supported equivalently |
| T98-TLS-010 | MUST NOT | NOT_STARTED | The secure TACACS+ listener never accepts a non-TLS TACACS connection |
| T98-TLS-011 | MUST | NOT_STARTED | TLS versions and algorithms follow BCP 195 and the TLS 1.3 mandatory implementation requirements |
| T98-TLS-012 | SHOULD | NOT_STARTED | Configuration can require TLS globally and per client without ambiguous automatic fallback |
| T98-TLS-013 | NOT RECOMMENDED | NOT_STARTED | Co-locating secure and legacy listeners on one host follows [ADR 0001](decisions/0001-all-in-one-dual-listener-lab.md) and presents a production warning |
| T98-TLS-014 | SHOULD/PROJECT | NOT_STARTED | New deployment examples prefer TLS; legacy mode is clearly marked compatibility-only |
| T98-TLS-015 | PROJECT MUST | NOT_STARTED | Default/reference port behavior is unambiguous: 49 legacy and 300 secure, with explicit override support |
| T98-CERT-001 | MUST | NOT_STARTED | Support certificate-based mutual authentication |
| T98-CERT-002 | MUST | NOT_STARTED | Validate remote certificate path |
| T98-CERT-003 | MUST | NOT_STARTED | Support configured certificate chains/bundles |
| T98-CERT-004 | MUST/Policy | NOT_STARTED | Invalid certificate is denied by default |
| T98-CERT-005 | MUST | NOT_STARTED | Server maps client certificate identity using supported network-address or SAN identity method |
| T98-CERT-006 | MUST | NOT_STARTED | Support SNI |
| T98-CERT-007 | MUST | NOT_STARTED | Support TLS 1.3 mandatory cipher suites offered by the Go TLS stack |
| T98-CERT-008 | SHOULD | NOT_STARTED | Cipher policy is configurable within safe supported options |
| T98-CERT-009 | MUST | NOT_STARTED | Revocation policy is implemented and documented |
| T98-CERT-010 | SHOULD | NOT_STARTED | TLS cached-information extension disposition documented |
| T98-CERT-011 | MUST | NOT_STARTED | Client certificate identification fields are configurable; dNSName and iPAddress SAN matching are supported |
| T98-CERT-012 | OPERATOR MUST/SHOULD | NOT_STARTED | Wildcard server identities follow RFC 9525 restrictions and are limited to a TACACS-only subdomain when used |
| T98-CERT-013 | PROJECT | NOT_STARTED | The baseline profile cannot silently disable certificate validation or mutual authentication |
| T98-CERT-014 | MUST | NOT_STARTED | Revocation checking applies to the selected certificate path mechanism and fails according to documented policy |
| T98-FLAG-001 | MUST | NOT_STARTED | Every TACACS packet over TLS has TAC_PLUS_UNENCRYPTED_FLAG set to 1 |
| T98-FLAG-002 | MUST | NOT_STARTED | Packet received over TLS without flag set returns type-specific ERROR with flag set and terminates session |
| T98-FLAG-003 | MUST | NOT_STARTED | Legacy shared-secret obfuscation keys are not used as TLS peer authentication |
| T98-RES-001 | SHOULD | NOT_STARTED | Client/server resumption behavior is supported or dispositioned |
| T98-RES-002 | SHOULD | NOT_STARTED | Ticket lifetime is configurable, including zero |
| T98-RES-003 | MUST NOT | NOT_STARTED | Accept or send 0-RTT TACACS+ data |
| T98-RES-004 | MUST NOT | NOT_STARTED | Include the TLS early_data extension |
| T98-RES-005 | MUST/SHOULD | NOT_STARTED | Certificate revocation implications during resumption are handled and documented |
| T98-RES-006 | SHOULD | NOT_STARTED | Server permits valid, unexpired, unused resumption tickets or records a stack limitation/ADR |
| T98-RES-007 | SHOULD | NOT_STARTED | Ticket reuse/linkability and TLS 1.3 client-tracking mitigations are reviewed and dispositioned |
| T98-RES-008 | PROJECT | NOT_STARTED | Resumption can be disabled for strict lab scenarios without changing normal full-handshake behavior |
| T98-OPT-001 | MAY | NOT_STARTED | External TLS 1.3 PSK |
| T98-OPT-002 | MUST if PSK implemented | NOT_STARTED | Support PSKs of at least 16 octets and identities of at least 16 octets |
| T98-OPT-003 | MUST NOT if PSK implemented | NOT_STARTED | Never reuse a legacy TACACS obfuscation shared secret as a TLS PSK |
| T98-OPT-004 | RECOMMENDED if PSK implemented | NOT_STARTED | Follow RFC 9257 external-PSK guidance |
| T98-OPT-005 | MAY/out of detailed scope | NOT_STARTED | Raw Public Keys |
| T98-ROLE-001 | CLIENT-ROLE MUST | NOT_STARTED | Test client begins TLS immediately and sends no TACACS data before handshake completion |
| T98-ROLE-002 | CLIENT-ROLE MUST NOT | NOT_STARTED | Test client never falls back to legacy after a TLS failure |
| T98-ROLE-003 | CLIENT-ROLE MUST | NOT_STARTED | Test client validates server identity using RFC 9525-supported DNS-ID/IP-ID/SRV-ID behavior; URI-ID is not used for server identity |
| T98-ROLE-004 | CLIENT-ROLE MUST | NOT_STARTED | Test client sends the unencrypted flag on every packet over TLS and terminates on a nonconforming server reply |
| T98-ROLE-005 | CLIENT-ROLE MUST NOT | NOT_STARTED | Test client sends no 0-RTT and includes no early-data extension |
| T98-ROLE-006 | OPERATOR SHOULD | NOT_STARTED | Production-like security tests run TLS-only or use separate hosts/instances for legacy and secure services |

