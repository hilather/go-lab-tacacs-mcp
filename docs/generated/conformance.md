# Generated TACACS+ and RADIUS conformance inventory

Do not hand-edit this file. Run `make generate`.

Sources: `testdata/conformance/rfc8907.yaml`, `testdata/conformance/rfc9887.yaml`, `testdata/conformance/rfc2865.yaml`, `testdata/conformance/rfc2866.yaml`, `testdata/conformance/rfc2869.yaml`, `testdata/conformance/rfc3579.yaml`, `testdata/conformance/rfc5080.yaml`, `testdata/conformance/project-radius.yaml`

## Qualification summary

| Gate | Result |
|---|---|
| RFC `MUST` / `MUST NOT` / `PROJECT MUST` | **PASS** (175/175 mandatory rows `PASS`) |
| Independent software peer | `internal/tacacs/testclient` (separate codec) |
| Cisco / second-NOS device interop | **SKIP** — no lab hardware; see `docs/INTEROP.md` |
| External TLS PSK / RPK | `DEFERRED_MAY` ([ADR 0006](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0006-external-psk-rpk.md)); T98-OPT-002/003/004 stay `NOT_STARTED` |

Mandatory RFC 8907/9887 server rows are qualified with linked evidence IDs. Device-family interop is not claimed.

## RADIUS qualification summary

| Gate | Result |
|---|---|
| RADIUS / project MVP rows | **PASS** (34/34 mandatory rows `PASS` or deferred with ADR evidence) |
| Advertised completeness | **Do not claim complete RADIUS** while Access-Challenge is deferred, external radclient is skipped, or any MVP row lacks evidence |
| Independent software peer | `internal/radius/testclient` (separate codec) |
| External radclient / Cisco IOL | **SKIP** unless recorded in `docs/INTEROP.md`; a skip is not RADIUS PASS |

RADIUS MVP MUST rows are evidenced or deferred with an ADR. Access-Challenge stays `DEFERRED_MAY`. External radclient/device interop is not claimed. Do **not** advertise complete RADIUS. TACACS 1.0 `-release` still gates only RFC 8907/9887.

## RFC 8907

RFC 8907 TACACS+

| ID | Level | Status | Requirement | Evidence |
|---|---|---|---|---|
| T89-H-001 | PROJECT MUST | PASS | Support TACACS+ major version 0xc and minor versions 0 and 1 in their valid contexts | unit:internal/tacacs/codec.TestDecodeEncodeRoundTrip; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix; golden:testdata/protocol/header/vectors.json |
| T89-H-002 | PROJECT MUST | PASS | Support Authentication, Authorization, and Accounting packet types | unit:internal/tacacs/codec.TestBodyCatalog; golden:testdata/protocol/bodies/; unit:internal/tacacs/testclient/codec (independent encode/decode) |
| T89-H-003 | MUST | PASS | First packet sequence is 1; client packets are odd and server packets are even | unit:internal/tacacs/codec.TestSequenceHappyPathAndParity; unit:internal/tacacs/codec.TestSequenceRejectsWrongOrder; fuzz:internal/tacacs/codec.FuzzSequence |
| T89-H-004 | MUST | PASS | Sequence numbers never wrap | unit:internal/tacacs/codec.TestSequenceWrap; golden:testdata/protocol/fuzz/sequence/seq-255.bin |
| T89-H-005 | MUST | PASS | Unknown header options or unsupported defined options produce ERROR and terminate when packet type is known | unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix; unit:internal/aaa.TestUnsupportedOptionsError; unit:internal/tacacs/server.TestSendAuthRejected; unit:internal/tacacs/server.TestWrongMinorAuthor |
| T89-H-006 | MUST | PASS | When packet type cannot be determined, return identical clear header with sequence incremented and zero body length as required | unit:internal/tacacs/codec.TestUnknownTypeZeroBodyReply; unit:internal/tacacs/server.TestUnknownTypeZeroBody; golden:testdata/protocol/header/unknown-type-error-reply.bin |
| T89-H-007 | MUST | PASS | Ignore unknown flag bits when reading and set them to zero when writing | unit:internal/tacacs/codec.TestUnknownFlagsIgnoredOnReadZeroedOnWrite; golden:testdata/protocol/fuzz/header/unknown-flags.bin |
| T89-H-008 | MUST | PASS | Session ID remains stable for the session; generated server-side IDs use cryptographic randomness where applicable | unit:internal/tacacs/codec.TestNewSessionID; unit:internal/tacacs/codec.TestSequenceHappyPathAndParity |
| T89-H-009 | MUST | PASS | Maximum accepted body size is configurable; default/recommended budget is 65536 bytes | unit:internal/tacacs/codec.TestBodyLengthBounds; unit:internal/tacacs/codec.TestDecodePacketRejectsHugeLengthBeforeArithmetic; bench:internal/tacacs/codec.BenchmarkHeaderDecode |
| T89-H-010 | MUST | PASS | Sum of decoded body component lengths exactly matches header body length | unit:internal/tacacs/codec.TestAuthenStartLengthMismatch; unit:internal/tacacs/codec.TestAuthorArgOverflowAndMismatch; fuzz:internal/tacacs/codec.FuzzDecodePacket |
| T89-H-011 | MUST | PASS | Bounded short-read handling for header and body | unit:internal/tacacs/codec.TestDecodeHeaderTruncation; unit:internal/tacacs/codec.TestDecodePacketShortBody; unit:internal/tacacs/server.TestPartialHeaderDisconnect; fuzz:internal/tacacs/codec.FuzzHeader |
| T89-H-012 | MUST | PASS | Username text follows the required UsernameCasePreserved profile | unit:internal/credentials.TestCanonicalUsernamePreservesCase; unit:internal/credentials.TestUsernameCanonicalLookup; fuzz:internal/credentials.FuzzCanonicalUsername; adr:docs/decisions/0002-password-kdf.md |
| T89-H-013 | MUST | PASS | Other text fields reject non-printable control characters where RFC requires printable US-ASCII | unit:internal/tacacs/codec.TestPrintableASCII; unit:internal/tacacs/codec.TestAuthenStartRejectsNonPrintablePort; golden:testdata/protocol/bodies/authen-start-port-control.bin |
| T89-H-014 | MUST | PASS | Arbitrary-byte data fields are not incorrectly treated as printable text | unit:internal/tacacs/codec.TestCHAPDecode; unit:internal/credentials.TestSplitCHAPAndMSCHAPLengths; golden:testdata/protocol/bodies/authen-start-chap.bin |
| T89-H-015 | MUST | PASS | A variable-length field whose encoded length is zero is ignored and treated as absent | unit:internal/tacacs/codec.TestZeroLengthFieldsAbsent; golden:testdata/protocol/bodies/authen-start-empty-fields.bin |
| T89-H-016 | PROJECT | PASS | All length arithmetic is overflow-safe before slicing or allocating | unit:internal/tacacs/codec.TestDecodePacketRejectsHugeLengthBeforeArithmetic; unit:internal/tacacs/codec.TestBodyLengthBounds; fuzz:internal/tacacs/codec.FuzzHeader |
| T89-L-001 | MUST | PASS | Accept connections only from configured known clients | unit:internal/tacacs/legacy.TestUnknownClientClosed; unit:internal/tacacs/legacy.TestMatchUnknown |
| T89-L-002 | MUST | PASS | Allow a unique shared secret per client | unit:internal/tacacs/legacy.TestDistinctClientSecrets; unit:internal/tacacs/legacy.TestCrossSecretIPv4IPv6 |
| T89-L-003 | MUST | PASS | Apply RFC 8907 packet-body obfuscation with flag clear | unit:internal/tacacs/codec.TestObfuscateIndependentVectors; golden:testdata/protocol/obfuscation/rfc8907-section-4.5.json |
| T89-L-004 | MUST NOT | PASS | Do not accept legacy packets with TAC_PLUS_UNENCRYPTED_FLAG set | unit:internal/tacacs/legacy.TestUnencryptedRejected; unit:internal/tacacs/legacy.TestUnencryptedDrainsLiveSession |
| T89-L-005 | MUST | PASS | Invalid shared secret or invalid decoded component lengths returns ERROR when possible | unit:internal/tacacs/legacy.TestWrongSecretAllFamilies; unit:internal/tacacs/codec.TestObfuscateWrongSecret |
| T89-L-006 | MUST | PASS | After a connection-level secret error, accept no new sessions and close after existing valid sessions complete | unit:internal/tacacs/legacy.TestUnencryptedDrainsLiveSession; unit:internal/tacacs/server.TestFlagErrorDrainsLiveSession |
| T89-L-007 | MUST | PASS | Shared-secret values are never logged or returned | unit:internal/tacacs/legacy.TestSecretCanaryNotOnWire; unit:internal/observability.TestFullCanaryMatrix; unit:internal/events.TestWriteJSONSecretCanary |
| T89-L-008 | PROJECT MUST | PASS | IPv4 and IPv6 configured client matching | unit:internal/tacacs/legacy.TestMatchIPv4LongestPrefix; unit:internal/tacacs/legacy.TestMatchIPv6LongestPrefix; unit:internal/tacacs/legacy.TestIPv6Match; unit:internal/config.TestClientIndexV4V6LongestPrefix |
| T89-L-009 | PROJECT | PASS | Longest-prefix then priority selection is deterministic; unresolved ties reject config | unit:internal/config.TestClientIndexAmbiguousSamePrefixAndPriority; unit:internal/state.TestSnapshotRejectsAmbiguousClients; unit:internal/config.TestClientIndexNoLexicographicTieBreakAtRuntime |
| T89-SC-001 | MUST | PASS | Negotiate single-connect only through the first request/reply flag exchange | unit:internal/tacacs/codec.TestSingleConnectNegotiation; unit:internal/tacacs/server.TestSingleConnectNegotiated |
| T89-SC-002 | MUST | PASS | Client cannot send a second packet before negotiation is established | unit:internal/tacacs/codec.TestSequencePrematureSecondPacket; unit:internal/tacacs/legacy.TestSecondSessionWaitsForFirstReply; unit:internal/tacacs/server.TestSecondSessionNotDispatchedBeforeFirstReply |
| T89-SC-003 | MUST | PASS | If single-connect is not established, close after the first session | unit:internal/tacacs/server.TestNonSingleConnectClosesAfterSession; unit:internal/tacacs/tls.TestNonSingleConnectCloses |
| T89-SC-004 | MAY | PASS | Server may refuse single-connect per client configuration | unit:internal/tacacs/server.TestRefuseSingleConnect |
| T89-SC-005 | PROJECT MUST | PASS | Multiplex sessions by session ID on one connection | unit:internal/tacacs/server.TestConcurrentSingleConnectSessions; race:internal/tacacs/server.TestConcurrentSingleConnectSessions |
| T89-SC-006 | PROJECT MUST | PASS | Preserve packet order within one session while allowing concurrency across sessions | race:internal/tacacs/server.TestConcurrentSingleConnectSessions; unit:internal/tacacs/legacy.TestInboxFullDoesNotStarveSibling |
| T89-SC-007 | MUST | PASS | Idle timeout is configurable and closes inactive single-connect connections | unit:internal/tacacs/server.TestIdleTimeout; unit:internal/tacacs/server.TestMaxLifetimeClosesConnection |
| T89-SC-008 | PROJECT MUST | PASS | Connection closure does not leak session goroutines or block server shutdown | unit:internal/tacacs/server.TestServeConnNoGoroutineLeak; unit:internal/tacacs/legacy.TestStartStopNoLeak; race:internal/tacacs/legacy.TestServeCancelDoesNotAbortInFlight |
| T89-SC-009 | PROJECT | PASS | Per-connection session cap and fair write serialization prevent resource starvation | unit:internal/tacacs/server.TestSessionCap; unit:internal/tacacs/server.TestEngineConnectionSaturation; unit:internal/tacacs/legacy.TestInboxFullDoesNotStarveSibling |
| T89-ACT-001 | PROJECT MUST | PASS | TAC_PLUS_AUTHEN_LOGIN | unit:internal/aaa.TestASCIILoginPassAndFail; unit:internal/aaa.TestPAPLoginPassAndFail; unit:internal/aaa.TestCHAPLoginIndependentVector; unit:internal/aaa.TestMSCHAPv1AndV2Vectors; interop:internal/tacacs/testclient + cmd/taclabd.TestRemainingAuthFlowsE2E |
| T89-ACT-002 | PROJECT MUST | PASS | TAC_PLUS_AUTHEN_CHPASS | unit:internal/aaa.TestCHPASSChangeAndReset; unit:internal/aaa.TestCHPASSOldIsGetDataNewIsGetPass |
| T89-ACT-003 | SHOULD NOT | PASS | TAC_PLUS_AUTHEN_SENDAUTH | unit:internal/aaa.TestUnsupportedOptionsError; unit:internal/tacacs/server.TestSendAuthRejected; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix |
| T89-ACT-004 | Removed | N/A_RFC_DEPRECATED | SENDPASS | unit:internal/aaa.TestUnsupportedOptionsError; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix; docs:docs/TACACS_CONFORMANCE.md SENDPASS removed |
| T89-TYPE-001 | PROJECT MUST | PASS | ASCII 0x01 | unit:internal/aaa.TestASCIILoginPassAndFail; unit:internal/aaa.TestASCIIMissingUserPrompts; lab:LAB-AUTH-001 |
| T89-TYPE-002 | PROJECT MUST | PASS | PAP 0x02 | unit:internal/aaa.TestPAPLoginPassAndFail; unit:internal/aaa.TestPAPMissingUserOrDataFails; lab:LAB-AUTH-003 |
| T89-TYPE-003 | PROJECT MUST | PASS | CHAP 0x03 | unit:internal/aaa.TestCHAPLoginIndependentVector; unit:internal/credentials.TestCHAPIndependentVectorsIncludePPPId; lab:LAB-AUTH-004 |
| T89-TYPE-004 | PROJECT MUST | PASS | MS-CHAP v1 0x05 | unit:internal/aaa.TestMSCHAPv1AndV2Vectors; unit:internal/credentials.TestMSCHAPv1IndependentVectorIncludesPPPId; unit:internal/tacacs/codec.TestMSCHAPExactLengths |
| T89-TYPE-005 | PROJECT MUST | PASS | MS-CHAP v2 0x06 | unit:internal/aaa.TestMSCHAPv1AndV2Vectors; unit:internal/credentials.TestMSCHAPv2RFC2759VectorIncludesPPPId; unit:internal/tacacs/codec.TestMSCHAPExactLengths |
| T89-TYPE-006 | PROJECT MUST | PASS | NOT_SET in authorization/accounting only | unit:internal/tacacs/server.TestAuthorBodyDecodes; unit:internal/aaa.TestAuthorizePreservesRequestFieldsAndDictionary |
| T89-TYPE-007 | PROJECT MUST | PASS | Unknown type | unit:internal/aaa.TestUnsupportedOptionsError; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix |
| T89-SVC-001 | PROJECT MUST | PASS | NONE 0x00 | unit:internal/tacacs/codec.TestKnownServices; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix; unit:internal/aaa.TestInvalidServiceFails |
| T89-SVC-002 | PROJECT MUST | PASS | LOGIN 0x01 | unit:internal/aaa.TestASCIILoginPassAndFail; unit:internal/tacacs/codec.TestKnownServices; lab:LAB-AUTH-001 |
| T89-SVC-003 | PROJECT MUST | PASS | ENABLE 0x02 | unit:internal/aaa.TestEnableIgnoresTypeGoldens; unit:internal/tacacs/codec.TestEnableGoldensIgnoreType; lab:LAB-AUTH-007 |
| T89-SVC-004 | PROJECT MUST | PASS | PPP 0x03 | unit:internal/tacacs/codec.TestKnownServices; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix; unit:internal/aaa.TestCHAPLoginIndependentVector |
| T89-SVC-005 | PROJECT MUST | PASS | PT 0x05 | unit:internal/tacacs/codec.TestKnownServices; unit:internal/aaa.TestAuthorizePreservesRequestFieldsAndDictionary |
| T89-SVC-006 | PROJECT MUST | PASS | RCMD 0x06 | unit:internal/tacacs/codec.TestKnownServices; unit:internal/policy.TestKnownDictionaryComplete |
| T89-SVC-007 | PROJECT MUST | PASS | X25 0x07 | unit:internal/tacacs/codec.TestKnownServices; unit:internal/policy.TestKnownDictionaryComplete |
| T89-SVC-008 | PROJECT MUST | PASS | NASI 0x08 | unit:internal/tacacs/codec.TestKnownServices; unit:internal/policy.TestKnownDictionaryComplete |
| T89-SVC-009 | PROJECT MUST | PASS | FWPROXY 0x09 | unit:internal/tacacs/codec.TestKnownServices; unit:internal/policy.TestKnownDictionaryComplete |
| T89-SVC-010 | PROJECT MUST | PASS | Unknown | unit:internal/aaa.TestInvalidServiceFails; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix |
| T89-AS-001 | MUST | PASS | PASS terminates successfully | unit:internal/aaa.TestASCIILoginPassAndFail; unit:internal/aaa.TestPAPLoginPassAndFail; lab:LAB-AUTH-001 |
| T89-AS-002 | MUST | PASS | FAIL terminates as authentication denial | unit:internal/aaa.TestASCIILoginPassAndFail; unit:internal/aaa.TestASCIIUnknownUserUniformFail; lab:LAB-AUTH-002 |
| T89-AS-003 | MUST | PASS | GETDATA continues and prompts for generic data | unit:internal/aaa.TestCHPASSOldIsGetDataNewIsGetPass; unit:internal/aaa.TestCHPASSChangeAndReset |
| T89-AS-004 | MUST | PASS | GETUSER continues and obtains username | unit:internal/aaa.TestASCIIMissingUserPrompts; unit:internal/aaa.TestASCIILoginPassAndFail |
| T89-AS-005 | MUST | PASS | GETPASS continues and uses NOECHO for secrets | unit:internal/aaa.TestASCIIMissingUserPrompts; unit:internal/aaa.TestCHPASSOldIsGetDataNewIsGetPass |
| T89-AS-006 | MUST | PASS | RESTART ends current session and allows client to start a new session ID/type | unit:internal/aaa.TestASCIIDisallowedRestarts; unit:internal/aaa.TestChallengeOnlyRestartsNonChallenge |
| T89-AS-007 | MUST | PASS | ERROR is distinct from FAIL and triggers unavailable-server handling semantics | unit:internal/aaa.TestUnsupportedOptionsError; unit:internal/aaa.TestCHAPMalformedIsError; unit:internal/tacacs/codec.TestDispositionAuthenStatus |
| T89-AS-008 | Deprecated | N/A_RFC_DEPRECATED | FOLLOW is not emitted; received/legacy behavior is safely failed | unit:internal/tacacs/codec.TestAuthenReplyFollow; unit:internal/policy.TestFOLLOWNeverEmittedAndErrorVsDeny |
| T89-AS-009 | MUST | PASS | Continue ABORT terminates the authentication session and safely records reason | unit:internal/aaa.TestAbortDropsSession; unit:internal/aaa.TestContinueAbortIsNotPass; unit:internal/aaa.TestCHPASSMismatchAndAbort |
| T89-AS-010 | MUST | PASS | Retry count is bounded; recommended default three | unit:internal/aaa.TestASCIIUnknownUserUniformFail; unit:internal/tacacs/codec.TestSequenceContinueLimit |
| T89-AS-011 | MUST | PASS | A defined authentication option not implemented by a selected profile returns TAC_PLUS_AUTHEN_STATUS_FAIL | unit:internal/aaa.TestInvalidServiceFails; unit:internal/aaa.TestCHPASSOnEnableServiceFails; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix; unit:internal/tacacs/codec.TestDispositionAuthenStatus |
| T89-AS-012 | SHOULD | PASS | GETDATA/GETUSER/GETPASS replies include usable prompt text | unit:internal/aaa.TestASCIIMissingUserPrompts; unit:internal/aaa.TestCHPASSOldIsGetDataNewIsGetPass; docs:internal/aaa/auth.go promptUser/promptPass |
| T89-AS-013 | SHOULD/MUST | PASS | Sensitive prompts set NOECHO and never reflect submitted secret material | unit:internal/aaa.TestASCIIMissingUserPrompts; unit:internal/aaa.TestCHPASSOldIsGetDataNewIsGetPass; unit:internal/observability.TestFullCanaryMatrix |
| T89-FLOW-001 | PROJECT MUST | PASS | ASCII LOGIN with username in START | unit:internal/aaa.TestASCIILoginPassAndFail; cmd:cmd/taclabd.TestVerticalSkeletonE2E; lab:LAB-AUTH-001 |
| T89-FLOW-002 | PROJECT MUST | PASS | ASCII LOGIN with GETUSER then GETPASS | unit:internal/aaa.TestASCIIMissingUserPrompts; unit:internal/aaa.TestASCIIUnknownUserUniformFail; unit:internal/aaa.TestAbortDropsSession |
| T89-FLOW-003 | PROJECT MUST | PASS | PAP LOGIN | unit:internal/aaa.TestPAPLoginPassAndFail; unit:internal/aaa.TestPAPMissingUserOrDataFails; unit:internal/tacacs/codec.TestClassifyAuthenStartMatrix; lab:LAB-AUTH-003 |
| T89-FLOW-004 | PROJECT MUST | PASS | CHAP LOGIN | unit:internal/aaa.TestCHAPLoginIndependentVector; unit:internal/aaa.TestCHAPMalformedIsError; unit:internal/credentials.TestCHAPIndependentVectorsIncludePPPId; lab:LAB-AUTH-004 |
| T89-FLOW-005 | PROJECT MUST | PASS | MS-CHAP v1 LOGIN | unit:internal/aaa.TestMSCHAPv1AndV2Vectors; unit:internal/credentials.TestMSCHAPv1IndependentVectorIncludesPPPId; unit:internal/tacacs/codec.TestMSCHAPExactLengths |
| T89-FLOW-006 | PROJECT MUST | PASS | MS-CHAP v2 LOGIN | unit:internal/aaa.TestMSCHAPv1AndV2Vectors; unit:internal/credentials.TestMSCHAPv2RFC2759VectorIncludesPPPId; unit:internal/aaa.TestMSCHAPv2MalformedIndependentOfUser |
| T89-FLOW-007 | PROJECT MUST | PASS | ENABLE | unit:internal/aaa.TestEnableIgnoresTypeGoldens; unit:internal/aaa.TestEnableWrongAndMissingVerifier; golden:testdata/protocol/bodies/authen-start-enable-ascii.bin; lab:LAB-AUTH-007 |
| T89-FLOW-008 | PROJECT MUST | PASS | ASCII CHPASS | unit:internal/aaa.TestCHPASSChangeAndReset; unit:internal/aaa.TestCHPASSMismatchAndAbort; unit:internal/aaa.TestCHPASSRevisionConflict; unit:internal/aaa.TestCHPASSClearsMustChangeLogin; unit:internal/state.TestOverrideLoginVerifierAndReset; unit:internal/state.TestOverrideLoginVerifierClearsMustChange |
| T89-FLOW-009 | PROJECT MUST | PASS | Unsupported defined option | unit:internal/aaa.TestUnsupportedOptionsError; unit:internal/tacacs/server.TestSendAuthRejected; unit:internal/tacacs/server.TestEOFIsNotPanic |
| T89-FLOW-010 | PROJECT MUST | PASS | ASCII CHPASS old/new prompt semantics | unit:internal/aaa.TestCHPASSOldIsGetDataNewIsGetPass; unit:internal/aaa.TestCHPASSMismatchAndAbort; unit:internal/credentials.TestChangeASCIIPasswordDoesNotTouchChallenge |
| T89-FLOW-011 | PROJECT MUST | PASS | ASCII unused data fields | unit:internal/aaa.TestASCIIIgnoresStartData |
| T89-FLOW-012 | PROJECT MUST | PASS | CHAP challenge policy | unit:internal/aaa.TestCHAPBelowMinimumChallengeErrors; unit:internal/credentials.TestCHAPRejectsShortChallenge |
| T89-FLOW-013 | PROJECT MUST | PASS | ASCII LOGIN after successful password + must_change_login may continue with GETPASS new/confirm (TacLab/vendor extension; not RFC 8907 LOGIN) when ascii_chpass is allowed; otherwise FAIL + Password change required | unit:internal/aaa.TestASCIILoginMustChangePromptsAndPass; unit:internal/aaa.TestASCIILoginMustChangeWhenCHPASSDisallowed; unit:internal/aaa.TestContinueASCIIDispatchesNeedNew; unit:internal/aaa.TestMustChangeDoesNotOverrideKindExpired |
| T89-FLOW-014 | PROJECT MUST | PASS | PAP/CHAP/MS-CHAP after successful verify + must_change_login FAIL with fixed server_msg; wrong password remains empty server_msg | unit:internal/aaa.TestPAPMustChangeFailsWithServerMsg; unit:internal/aaa.TestPAPWrongPasswordEmptyServerMsg; unit:internal/aaa.TestCHAPMustChangeFailsAfterGoodResponse; unit:internal/aaa.TestMSCHAPMustChangeFailsAfterGoodResponse |
| T89-FLOW-015 | PROJECT MUST | PASS | ENABLE after successful secret + must_change_enable continues GETPASS new/confirm (TacLab/vendor extension; not RFC 8907 ENABLE). OverrideEnableVerifier clears must_change_enable. Does not gate login-class merge. | unit:internal/aaa.TestEnableMustChangePromptsAndPass; unit:internal/aaa.TestContinueEnableDispatchesNeedNew; unit:internal/aaa.TestEnableMustChangeLoginDoesNotForceChange; unit:internal/aaa.TestCHPASSOnEnableStillFailsWithMustChangeEnable; unit:internal/state.TestOverrideEnableVerifierClearsMustChange; unit:internal/state.TestYAMLMustChangeEnableRestoredAfterSuccessfulChangeAndReset; unit:internal/state.TestOverrideEnableVerifierAndReset |
| T89-AU-001 | MUST | PASS | Decode all request fields and preserve user, port, remote address, auth context, and ordered arguments | unit:internal/aaa.TestAuthorizePreservesRequestFieldsAndDictionary; unit:internal/tacacs/codec.TestAuthorRequestArgsOrder; golden:testdata/protocol/bodies/author-request-shell-show.bin |
| T89-AU-002 | MUST NOT | PASS | Do not trust authen_method for policy evaluation | unit:internal/policy.TestAuthenMethodObservational; unit:internal/aaa.TestAuthenMethodCodesRecordedNotTrusted |
| T89-AU-003 | MUST | PASS | Recognize all authen-method codes for parsing/events | unit:internal/aaa.TestAuthenMethodCodesRecordedNotTrusted; unit:internal/tacacs/server.TestBridgeAuthenMethodNotType |
| T89-AU-004 | MUST | PASS | Parse mandatory = and optional * separators at the first separator only | unit:internal/tacacs/codec.TestParseArgument; fuzz:internal/tacacs/codec.FuzzParseArgument; unit:internal/policy.TestAVOrderDuplicatesAndSeparators |
| T89-AU-005 | MUST | PASS | Preserve duplicate and ordered AV pairs | unit:internal/policy.TestAVOrderDuplicatesAndSeparators; golden:testdata/protocol/bodies/author-request-dup-optional.bin |
| T89-AU-006 | MUST | PASS | Enforce AV-pair encoded length 2 through 255 bytes | unit:internal/policy.TestNumericLengthCheckedBeforeParse; unit:internal/tacacs/codec.TestAuthorArgOverflowAndMismatch |
| T89-AU-007 | MUST | PASS | PASS_ADD with zero response args approves without modification | unit:internal/aaa.TestPASSAddZeroArgsForCommand; unit:internal/tacacs/codec.TestAuthorResponseStatuses |
| T89-AU-008 | MUST | PASS | PASS_ADD appends/applies returned arguments correctly | unit:internal/policy.TestGoldenPersonas; unit:internal/tacacs/server.TestLiveAuthorPacketsTwoEvaluators; lab:LAB-AUTHZ-001 |
| T89-AU-009 | MUST | PASS | PASS_REPL replaces request arguments with response arguments | unit:internal/policy.TestPersonasSessionVersusCommand; unit:internal/tacacs/codec.TestAuthorResponseStatuses; golden:testdata/protocol/bodies/author-response-pass-repl.bin |
| T89-AU-010 | MUST | PASS | FAIL denies the request | unit:internal/policy.TestDefaultDenyUnknownAndDisabled; unit:internal/aaa.TestReadonlyConfigureDeniesWithoutServiceSteps; lab:LAB-AUTHZ-003 |
| T89-AU-011 | MUST | PASS | ERROR signals server processing failure, not policy denial | unit:internal/policy.TestFOLLOWNeverEmittedAndErrorVsDeny; unit:internal/policy.TestResponseArgumentLimitIsError |
| T89-AU-012 | Deprecated | N/A_RFC_DEPRECATED | FOLLOW is not emitted | unit:internal/policy.TestFOLLOWNeverEmittedAndErrorVsDeny; unit:internal/tacacs/codec.TestAuthorResponseStatuses |
| T89-AU-013 | MUST | PASS | Unknown mandatory response arguments are never generated accidentally | unit:internal/policy.TestCompileRejectsBadRegexAndBadReply; unit:internal/policy.TestKnownDictionaryComplete |
| T89-AU-014 | PROJECT MUST | PASS | Arbitrary vendor AV pairs can be matched, preserved, and returned | unit:internal/aaa.TestVendorFixturesThroughEvaluators; golden:testdata/vendors/fixtures.yaml |
| T89-AU-015 | PROJECT | PASS | Default deny when no deterministic rule matches | unit:internal/policy.TestDefaultDenyUnknownAndDisabled; unit:internal/aaa.TestServicePermitNeverAuthorizesCommand |
| T89-AU-016 | PROJECT | PASS | Full explanation trace is stable and redacted | unit:internal/aaa.TestLiveAndExplainIdentical; unit:internal/aaa.TestSensitiveRequestAVsRedactedInTrace; golden:testdata/policies/goldens/ |
| T89-AU-017 | SHOULD/PROJECT MUST | PASS | Support the complete RFC 8907 common authorization argument dictionary | unit:internal/policy.TestKnownDictionaryComplete; unit:internal/aaa.TestAuthorizePreservesRequestFieldsAndDictionary |
| T89-AU-018 | MUST | PASS | Numeric argument lengths are checked before conversion; unrepresentable values are handled as unsupported arguments | unit:internal/policy.TestNumericLengthCheckedBeforeParse; unit:internal/tacacs/codec.TestAuthorArgOverflowAndMismatch |
| T89-AU-019 | MUST | PASS | Absolute times use UTC unless an explicit timezone argument is present | unit:internal/policy.TestEpochUTCUnlessTimezone; unit:internal/aaa.TestTimezoneAppliedToPacketTimes |
| T89-AU-020 | PROJECT MUST | PASS | Validate/preserve the required primary service argument for supported use cases | unit:internal/policy.TestProtocolMatchAndEmptyCmdFromAV; unit:internal/aaa.TestAuthorizeServiceVsCommand |
| T89-AU-021 | PROJECT MUST | PASS | Shell command authorization preserves and validates cmd plus ordered cmd-arg values | unit:internal/policy.TestPersonasSessionVersusCommand; unit:internal/aaa.TestServicePermitNeverAuthorizesCommand; golden:testdata/policies/goldens/readonly-configure.json; lab:LAB-AUTHZ-002 |
| T89-AV-001 | PROJECT MUST | PASS | service | unit:internal/policy.TestKnownDictionaryComplete; unit:internal/policy.TestGoldenPersonas |
| T89-AV-002 | PROJECT MUST | PASS | protocol | unit:internal/policy.TestProtocolMatchAndEmptyCmdFromAV |
| T89-AV-003 | PROJECT MUST | PASS | cmd | unit:internal/policy.TestPersonasSessionVersusCommand; golden:testdata/policies/goldens/ |
| T89-AV-004 | PROJECT MUST | PASS | cmd-arg | unit:internal/policy.TestAVOrderDuplicatesAndSeparators; unit:internal/aaa.TestCommandAccounting |
| T89-AV-005 | PROJECT MUST | PASS | acl | unit:internal/policy.TestKnownDictionaryComplete; unit:internal/policy.TestValidateValueEncodings |
| T89-AV-006 | PROJECT MUST | PASS | inacl | unit:internal/policy.TestKnownDictionaryComplete; unit:internal/policy.TestValidateValueEncodings |
| T89-AV-007 | PROJECT MUST | PASS | outacl | unit:internal/policy.TestKnownDictionaryComplete; unit:internal/policy.TestValidateValueEncodings |
| T89-AV-008 | PROJECT MUST | PASS | addr | unit:internal/policy.TestValidateValueEncodings |
| T89-AV-009 | PROJECT MUST | PASS | addr-pool | unit:internal/policy.TestKnownDictionaryComplete |
| T89-AV-010 | PROJECT MUST | PASS | timeout | unit:internal/policy.TestValidateValueEncodings |
| T89-AV-011 | PROJECT MUST | PASS | idletime | unit:internal/policy.TestValidateValueEncodings |
| T89-AV-012 | PROJECT MUST | PASS | autocmd | unit:internal/policy.TestKnownDictionaryComplete |
| T89-AV-013 | PROJECT MUST | PASS | noescape | unit:internal/policy.TestValidateValueEncodings |
| T89-AV-014 | PROJECT MUST | PASS | nohangup | unit:internal/policy.TestValidateValueEncodings |
| T89-AV-015 | PROJECT MUST | PASS | priv-lvl | unit:internal/policy.TestPrivilegeBounds; unit:internal/policy.TestGoldenPersonas |
| T89-AV-016 | PROJECT MUST | PASS | vendor/unknown | unit:internal/aaa.TestVendorFixturesThroughEvaluators; unit:internal/policy.TestAVOrderDuplicatesAndSeparators |
| T89-PRIV-001 | MUST | PASS | Accept and preserve levels 0 through 15 | unit:internal/policy.TestPrivilegeBounds; unit:internal/policy.TestGoldenPersonas |
| T89-PRIV-002 | MUST | PASS | Reject values outside the encoded field/rule range | unit:internal/policy.TestPrivilegeBounds |
| T89-PRIV-003 | SHOULD | PASS | Support session-based shell authorization returning priv-lvl | unit:internal/policy.TestGoldenPersonas; lab:LAB-AUTHZ-001 |
| T89-PRIV-004 | MUST | PASS | ENABLE flow can request a higher privilege without assuming prior auth by protocol | unit:internal/aaa.TestEnableIgnoresTypeGoldens; unit:internal/aaa.TestEnableWrongAndMissingVerifier; lab:LAB-AUTH-007 |
| T89-PRIV-005 | PROJECT | PASS | Policy does not assume vendor command mappings for a privilege level | unit:internal/policy.TestPersonasSessionVersusCommand; unit:internal/aaa.TestServicePermitNeverAuthorizesCommand |
| T89-AC-001 | MUST | PASS | START flag only (0x02) | unit:internal/aaa.TestRecordAccountingStart; unit:internal/tacacs/codec.TestAcctFlagTable; lab:LAB-ACCT-001 |
| T89-AC-002 | MUST | PASS | STOP flag only (0x04) | unit:internal/aaa.TestAccountingFlagTable; lab:LAB-ACCT-001 |
| T89-AC-003 | MUST | PASS | WATCHDOG no update (0x08), arguments ignored as required | unit:internal/aaa.TestWatchdogIgnoresArguments; unit:internal/tacacs/codec.TestAcctWatchdogIgnoresArgsOnEncode |
| T89-AC-004 | MUST | PASS | WATCHDOG with update (0x0a) | unit:internal/aaa.TestWatchdogUpdateKeepsArguments |
| T89-AC-005 | MUST | PASS | Reject no flags, START+STOP, WATCHDOG+STOP, and other invalid combinations with ERROR | unit:internal/aaa.TestAccountingFullByteTable; unit:internal/aaa.TestRecordAccountingRejectsInvalidFlags; lab:LAB-ACCT-003 |
| T89-AC-006 | MUST | PASS | Return SUCCESS only after the record is accepted by the authoritative sink | unit:internal/aaa.TestSuccessOnlyAfterRingAccept; unit:internal/aaa.TestCanceledContextNoSuccess |
| T89-AC-007 | MUST | PASS | Return ERROR when the record cannot be accepted | unit:internal/aaa.TestSuccessOnlyAfterRingAccept; unit:internal/aaa.TestTooManyAccountingArgs |
| T89-AC-008 | Deprecated | N/A_RFC_DEPRECATED | FOLLOW is not emitted | unit:internal/tacacs/codec.TestAcctReplyAndFollow; unit:internal/aaa.TestAccountingFlagTable |
| T89-AC-009 | MUST | PASS | Preserve authentication/authorization context and ordered AV pairs | unit:internal/aaa.TestAccountingPreservesHeaderContext; unit:internal/aaa.TestAccountingPreservesAVOrder |
| T89-AC-010 | PROJECT MUST | PASS | Command accounting supports service, cmd, and ordered cmd-arg | unit:internal/aaa.TestCommandAccounting |
| T89-AC-011 | PROJECT | PASS | Ring overwrite is bounded, observable, and does not block current acknowledgement | unit:internal/events.TestOverwriteDoesNotBlockAccept; unit:internal/events.TestOverwriteOldest |
| T89-AC-012 | MUST | PASS | task_id is treated as opaque; the server makes no format assumptions | unit:internal/aaa.TestTaskIDIsOpaque |
| T89-AC-013 | PROJECT MUST | PASS | Accounting-only arguments and following authorization arguments retain wire order | unit:internal/aaa.TestAccountingPreservesAVOrder |
| T89-AC-014 | SHOULD/PROJECT MUST | PASS | Common accounting string, numeric, Boolean, address, and time representations are accepted and displayed consistently | unit:internal/aaa.TestAccountingDictionaryEncodings; unit:internal/aaa.TestAccountingDictionaryComplete |
| T89-ACAV-001 | PROJECT MUST | PASS | task_id | unit:internal/aaa.TestTaskIDIsOpaque; unit:internal/aaa.TestAccountingDictionaryComplete |
| T89-ACAV-002 | PROJECT MUST | PASS | start_time | unit:internal/aaa.TestAccountingDictionaryEncodings; unit:internal/aaa.TestTimezoneAppliedToPacketTimes |
| T89-ACAV-003 | PROJECT MUST | PASS | stop_time | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-004 | PROJECT MUST | PASS | elapsed_time | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-005 | PROJECT MUST | PASS | timezone | unit:internal/aaa.TestTimezoneAppliedToPacketTimes |
| T89-ACAV-006 | PROJECT MUST | PASS | event | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-007 | PROJECT MUST | PASS | reason | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-008 | PROJECT MUST | PASS | bytes | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-009 | PROJECT MUST | PASS | bytes_in | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-010 | PROJECT MUST | PASS | bytes_out | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-011 | PROJECT MUST | PASS | paks | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-012 | PROJECT MUST | PASS | paks_in | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-013 | PROJECT MUST | PASS | paks_out | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-014 | PROJECT MUST | PASS | err_msg | unit:internal/aaa.TestAccountingDictionaryEncodings |
| T89-ACAV-015 | PROJECT MUST | PASS | authorization args | unit:internal/aaa.TestAccountingPreservesAVOrder |
| T89-ACAV-016 | PROJECT MUST | PASS | vendor/unknown | unit:internal/aaa.TestAccountingPreservesAVOrder; unit:internal/aaa.TestVendorFixturesThroughEvaluators |
| T89-SEC-001 | MUST | PASS | Administrator can restrict authentication to challenge-response types | unit:internal/aaa.TestChallengeOnlyRestartsNonChallenge; unit:internal/aaa.TestASCIIDisallowedRestarts |
| T89-SEC-002 | SHOULD | DISPOSITIONED_SHOULD | Warn when ASCII/PAP are enabled and document that non-challenge methods should be enabled only when required | adr:docs/decisions/0012-ascii-pap-enablement-warning.md; docs:docs/OPERATOR.md; docs:configs/lab.example.yaml comment; unit:internal/aaa.TestChallengeOnlyRestartsNonChallenge |
| T89-SEC-003 | SHOULD NOT | PASS | Avoid reusing the same credential across challenge and non-challenge types | unit:internal/credentials.TestNoFallbackAcrossCredentialClasses; unit:internal/credentials.TestChangeASCIIPasswordDoesNotTouchChallenge; adr:docs/decisions/0002-password-kdf.md |
| T89-SEC-004 | SHOULD NOT | PASS | SENDAUTH/SENDPASS are not implemented; any future implementation is disabled by default with a warning | unit:internal/aaa.TestUnsupportedOptionsError; unit:internal/tacacs/server.TestSendAuthRejected |
| T89-SEC-005 | MUST | PASS | Redirection/FOLLOW is deprecated, not advertised, and disabled | unit:internal/policy.TestFOLLOWNeverEmittedAndErrorVsDeny; unit:internal/tacacs/codec.TestAuthenReplyFollow; unit:internal/tacacs/codec.TestAcctReplyAndFollow |
| T89-SEC-006 | MUST | PASS | A dedicated legacy shared secret can be configured for each individual client | unit:internal/tacacs/legacy.TestDistinctClientSecrets; unit:internal/config.TestValidateLegacySecretRequired |
| T89-SEC-007 | MUST/PROJECT MUST | PASS | Every enabled legacy client has a shared secret and cleartext legacy packet bodies are rejected | unit:internal/config.TestValidateLegacySecretRequired; unit:internal/tacacs/legacy.TestUnencryptedRejected |
| T89-SEC-008 | PROJECT | PASS | Operator UI clearly labels legacy transport as compatibility/insecure | docs:web/src/pages/DashboardPage.tsx colocated_topology banner; unit:cmd/taclabd.TestEmitLifecycleWarningsSkipsTLSOnly; docs:docs/OPERATOR.md |
| T89-SEC-009 | MUST | PASS | Shared secrets are treated as sensitive and never leaked, logged, exported, traced, or returned | unit:internal/observability.TestFullCanaryMatrix; unit:internal/credentials.TestSecretNonSerialization; unit:internal/tacacs/legacy.TestSecretCanaryNotOnWire |
| T89-SEC-010 | MUST | PASS | Shared keys of at least 32 characters are supported without truncation | unit:internal/config.TestCheckSharedSecretPolicy; unit:internal/config.TestEvaluateSecretsReuseAndLifecycle |
| T89-SEC-011 | MUST | PASS | Configuration supports an enforceable minimum-complexity policy for legacy shared keys | unit:internal/config.TestCheckSharedSecretPolicy; unit:internal/config.TestEvaluateSecretsRejectsWeakWithoutEcho |
| T89-SEC-012 | MUST | PASS | Management metadata can track shared-key lifetime and notify operators that rotation is due | unit:internal/config.TestSecretLifecycleDueSoonAndCurrent; unit:internal/config.TestEvaluateSecretsReuseAndLifecycle |
| T89-SEC-013 | SHOULD | PASS | Validation warns when process-local keyed HMAC comparison detects that multiple clients reuse the same shared secret; no comparison value is exposed or persisted | unit:internal/config.TestEvaluateSecretsReuseAndLifecycle; unit:internal/config.TestEvaluateSecretsRejectsWeakWithoutEcho |
| T89-SEC-014 | OPERATOR SHOULD | PASS | Generated/operator-provided legacy keys are at least 16 characters and rotated regularly | docs:docs/OPERATOR.md; unit:tools/labgen generates >=32-char unique secrets; docs:docs/CONFIGURATION.md security.legacy_shared_secrets |
| T89-SEC-015 | OPERATOR MUST | PASS | Legacy TACACS is documented for a protected, integrity-preserving management network; operators are warned not to rely on obfuscation | docs:docs/OPERATOR.md; docs:docs/LAB_DEPLOYMENT.md; docs:docs/decisions/0001-all-in-one-dual-listener-lab.md |
| T89-SEC-016 | PROJECT | PASS | Configuration and deployment make secure TACACS+ the recommended mode for new lab topologies | docs:deployments/compose/compose.tls-only.yaml; docs:docs/OPERATOR.md; lab:tools/lab-test.sh TLS-only phase |

## RFC 9887

RFC 9887 Secure TACACS+

| ID | Level | Status | Requirement | Evidence |
|---|---|---|---|---|
| T98-TLS-001 | MUST | PASS | Secure TACACS+ listens on a port distinct from legacy | unit:cmd/taclabd.TestServeTLSOnlyPlaintextRejected; unit:internal/tacacs/tls.TestNoFallbackToLegacy; docs:deployments/compose/compose.yaml |
| T98-TLS-002 | PROJECT MUST | PASS | Support the well-known secure TACACS+ TCP port 300 through the reference deployment mapping | lab:make lab-test host 300 mapping; docs:deployments/compose/compose.yaml |
| T98-TLS-003 | MUST | PASS | Begin TLS handshake immediately; no plaintext preface or upgrade | unit:internal/tacacs/tls.TestPlaintextOnTLSPortRejected; lab:LAB-TLS-003 |
| T98-TLS-004 | MUST | PASS | Minimum TLS version 1.3; TLS 1.2 and earlier rejected | unit:internal/tacacs/tls.TestTLS12Rejected; unit:internal/tacacs/testclient.TestDialTLSNoFallbackOnTLS12 |
| T98-TLS-005 | MUST | PASS | Encrypt all TACACS+ data as TLS application data | unit:internal/tacacs/tls.TestMTLSRoundTrip; unit:internal/tacacs/tls.TestNoObfuscationOverTLS; lab:LAB-TLS-001 |
| T98-TLS-006 | MUST | PASS | Do not apply legacy TACACS+ obfuscation over TLS | unit:internal/tacacs/tls.TestNoObfuscationOverTLS; unit:internal/tacacs/tls.TestObfuscationKeyNotUsedForTLS |
| T98-TLS-007 | MUST | PASS | Non-single-connect TLS connection closes after session completion | unit:internal/tacacs/tls.TestNonSingleConnectCloses |
| T98-TLS-008 | MAY | PASS | Single-connect TLS sessions persist until idle/other closure | unit:internal/tacacs/server.TestSingleConnectNegotiated; unit:internal/tacacs/tls.TestMTLSRoundTrip |
| T98-TLS-009 | PROJECT MUST | PASS | IPv4 and IPv6 supported equivalently | unit:internal/tacacs/tls.TestIPv6Match; unit:internal/config.TestClientIndexV4V6LongestPrefix |
| T98-TLS-010 | MUST NOT | PASS | The secure TACACS+ listener never accepts a non-TLS TACACS connection | unit:internal/tacacs/tls.TestPlaintextOnTLSPortRejected; unit:cmd/taclabd.TestServeTLSOnlyPlaintextRejected; lab:LAB-TLS-003 |
| T98-TLS-011 | MUST | PASS | TLS versions and algorithms follow BCP 195 and the TLS 1.3 mandatory implementation requirements | unit:internal/tacacs/tls.TestTLS12Rejected; unit:internal/tacacs/tls.TestMandatoryCipherSuiteNegotiated; adr:docs/decisions/0004-tls13-cipher-policy.md |
| T98-TLS-012 | SHOULD | PASS | Configuration can require TLS globally and per client without ambiguous automatic fallback | unit:internal/tacacs/tls.TestNoFallbackToLegacy; unit:internal/tacacs/legacy.TestTLSClientHelloNotRouted; docs:deployments/compose/compose.tls-only.yaml |
| T98-TLS-013 | NOT RECOMMENDED | PASS | Co-locating secure and legacy listeners on one host follows [ADR 0001](decisions/0001-all-in-one-dual-listener-lab.md) and presents a production warning | adr:docs/decisions/0001-all-in-one-dual-listener-lab.md; unit:cmd/taclabd.TestEmitLifecycleWarningsSkipsTLSOnly; docs:docs/OPERATOR.md |
| T98-TLS-014 | SHOULD/PROJECT | PASS | New deployment examples prefer TLS; legacy mode is clearly marked compatibility-only | docs:deployments/compose/compose.tls-only.yaml; docs:docs/OPERATOR.md; docs:web/src/pages/DashboardPage.tsx colocated warning |
| T98-TLS-015 | PROJECT MUST | PASS | Default/reference port behavior is unambiguous: 49 legacy and 300 secure, with explicit override support | docs:deployments/compose/compose.yaml 49/300; lab:make lab-test; docs:configs/lab.example.yaml advertised_port |
| T98-CERT-001 | MUST | PASS | Support certificate-based mutual authentication | unit:internal/tacacs/tls.TestMTLSRoundTrip; lab:LAB-TLS-001 |
| T98-CERT-002 | MUST | PASS | Validate remote certificate path | unit:internal/tacacs/tls.TestUnknownCARejected; unit:internal/tacacs/tls.TestExpiredClientRejected; unit:internal/tacacs/tls.TestFutureClientRejected |
| T98-CERT-003 | MUST | PASS | Support configured certificate chains/bundles | unit:internal/tacacs/tls.TestIntermediateChainPresented; unit:internal/tacacs/tls.TestCertificateFileRotation |
| T98-CERT-004 | MUST/Policy | PASS | Invalid certificate is denied by default | unit:internal/tacacs/tls.TestMissingClientCertRejected; unit:internal/tacacs/tls.TestUnauthorizedValidCertRejected; lab:LAB-TLS-002 |
| T98-CERT-005 | MUST | PASS | Server maps client certificate identity using supported network-address or SAN identity method | unit:internal/tacacs/tls.TestIPSANMatch; unit:internal/tacacs/tls.TestMTLSRoundTrip |
| T98-CERT-006 | MUST | PASS | Support SNI | unit:internal/tacacs/tls.TestSNISelectsProfile; unit:internal/tacacs/tls.TestUnknownSNIRejected; unit:internal/tacacs/tls.TestRequireSNIRejectsEmpty |
| T98-CERT-007 | MUST | PASS | Support TLS 1.3 mandatory cipher suites offered by the Go TLS stack | unit:internal/tacacs/tls.TestMandatoryCipherSuiteNegotiated; adr:docs/decisions/0004-tls13-cipher-policy.md |
| T98-CERT-008 | SHOULD | DISPOSITIONED_SHOULD | Cipher policy is configurable within safe supported options | adr:docs/decisions/0004-tls13-cipher-policy.md; unit:internal/tacacs/tls.TestMandatoryCipherSuiteNegotiated |
| T98-CERT-009 | MUST | PASS | Revocation policy is implemented and documented | unit:internal/tacacs/tls.TestRevokedClientRejected; unit:internal/tacacs/tls.TestWrongIssuerCRLDoesNotAdmit; docs:docs/OPERATOR.md revocation.mode configured_crl |
| T98-CERT-010 | SHOULD | DISPOSITIONED_SHOULD | TLS cached-information extension disposition documented | adr:docs/decisions/0003-cached-information.md |
| T98-CERT-011 | MUST | PASS | Client certificate identification fields are configurable; dNSName and iPAddress SAN matching are supported | unit:internal/tacacs/tls.TestIPSANMatch; unit:internal/config.TestValidateRejectsInvalidIPSAN; unit:internal/state.TestSnapshotCertificateOnly |
| T98-CERT-012 | OPERATOR MUST/SHOULD | PASS | Wildcard server identities follow RFC 9525 restrictions and are limited to a TACACS-only subdomain when used | unit:internal/config.TestValidateRejectsNonTACACSWildcard; unit:internal/tacacs/tls.TestValidateWildcardServerName; unit:internal/tacacs/tls.TestWildcardServerIdentity |
| T98-CERT-013 | PROJECT | PASS | The baseline profile cannot silently disable certificate validation or mutual authentication | unit:internal/config.TestValidateSecureTLSRequiresIdentity; unit:internal/tacacs/tls.TestMissingClientCertRejected |
| T98-CERT-014 | MUST | PASS | Revocation checking applies to the selected certificate path mechanism and fails according to documented policy | unit:internal/tacacs/tls.TestRevokedClientRejected; unit:internal/tacacs/tls.TestResumeRechecksRevocation; unit:internal/config.TestValidateRejectsRevocationRecheckDisabled |
| T98-FLAG-001 | MUST | PASS | Every TACACS packet over TLS has TAC_PLUS_UNENCRYPTED_FLAG set to 1 | unit:internal/tacacs/tls.TestMissingUnencryptedFlagErrors; unit:internal/tacacs/testclient.TestTLSForcesUnencryptedAndRejectsClearFlag |
| T98-FLAG-002 | MUST | PASS | Packet received over TLS without flag set returns type-specific ERROR with flag set and terminates session | unit:internal/tacacs/tls.TestMissingUnencryptedFlagErrors; unit:internal/tacacs/testclient.TestTLSForcesUnencryptedAndRejectsClearFlag |
| T98-FLAG-003 | MUST | PASS | Legacy shared-secret obfuscation keys are not used as TLS peer authentication | unit:internal/tacacs/tls.TestObfuscationKeyNotUsedForTLS; unit:internal/credentials.TestSecretPurposes |
| T98-RES-001 | SHOULD | PASS | Client/server resumption behavior is supported or dispositioned | unit:internal/tacacs/tls.TestSessionResumption; bench:internal/tacacs/tls.BenchmarkResumedHandshake; adr:docs/decisions/0005-ticket-lifetime.md |
| T98-RES-002 | SHOULD | DISPOSITIONED_SHOULD | Ticket lifetime is configurable, including zero | adr:docs/decisions/0005-ticket-lifetime.md; unit:internal/config.TestValidateRejectsUnenforceableTicketLifetime; unit:internal/tacacs/tls.TestTicketLifetimeZeroDisables |
| T98-RES-003 | MUST NOT | PASS | Accept or send 0-RTT TACACS+ data | unit:internal/tacacs/tls.TestEarlyDataExtensionRejected; unit:internal/config.TestValidateRejectsEarlyDataDisabled |
| T98-RES-004 | MUST NOT | PASS | Include the TLS early_data extension | unit:internal/tacacs/tls.TestEarlyDataExtensionRejected; unit:internal/tacacs/testclient.TestDialTLSClientHelloHasNoEarlyData |
| T98-RES-005 | MUST/SHOULD | PASS | Certificate revocation implications during resumption are handled and documented | unit:internal/tacacs/tls.TestResumeRechecksRevocation; unit:internal/config.TestValidateRejectsRevocationRecheckDisabled; adr:docs/decisions/0005-ticket-lifetime.md |
| T98-RES-006 | SHOULD | PASS | Server permits valid, unexpired, unused resumption tickets or records a stack limitation/ADR | unit:internal/tacacs/tls.TestSessionResumption; adr:docs/decisions/0005-ticket-lifetime.md |
| T98-RES-007 | SHOULD | DISPOSITIONED_SHOULD | Ticket reuse/linkability and TLS 1.3 client-tracking mitigations are reviewed and dispositioned | adr:docs/decisions/0005-ticket-lifetime.md |
| T98-RES-008 | PROJECT | PASS | Resumption can be disabled for strict lab scenarios without changing normal full-handshake behavior | unit:internal/tacacs/tls.TestResumptionDisabled; unit:internal/tacacs/tls.TestTicketLifetimeZeroDisables |
| T98-OPT-001 | MAY | DEFERRED_MAY | External TLS 1.3 PSK | adr:docs/decisions/0006-external-psk-rpk.md |
| T98-OPT-002 | MUST if PSK implemented | NOT_STARTED | Support PSKs of at least 16 octets and identities of at least 16 octets |  |
| T98-OPT-003 | MUST NOT if PSK implemented | NOT_STARTED | Never reuse a legacy TACACS obfuscation shared secret as a TLS PSK |  |
| T98-OPT-004 | RECOMMENDED if PSK implemented | NOT_STARTED | Follow RFC 9257 external-PSK guidance |  |
| T98-OPT-005 | MAY/out of detailed scope | DEFERRED_MAY | Raw Public Keys | adr:docs/decisions/0006-external-psk-rpk.md |
| T98-ROLE-001 | CLIENT-ROLE MUST | PASS | Test client begins TLS immediately and sends no TACACS data before handshake completion | unit:internal/tacacs/testclient.TestDialTLSBeginsImmediately; unit:internal/tacacs/testclient.TestDialTLSNoPacketBeforeHandshakeReturns |
| T98-ROLE-002 | CLIENT-ROLE MUST NOT | PASS | Test client never falls back to legacy after a TLS failure | unit:internal/tacacs/testclient.TestDialTLSNoFallbackOnPlaintextPeer; unit:internal/tacacs/testclient.TestDialTLSNoFallbackOnTLS12 |
| T98-ROLE-003 | CLIENT-ROLE MUST | PASS | Test client validates server identity using RFC 9525-supported DNS-ID/IP-ID/SRV-ID behavior; URI-ID is not used for server identity | unit:internal/tacacs/testclient.TestServerIdentityMatrix; unit:internal/tacacs/testclient.TestDialTLSIdentityKindsOverWire |
| T98-ROLE-004 | CLIENT-ROLE MUST | PASS | Test client sends the unencrypted flag on every packet over TLS and terminates on a nonconforming server reply | unit:internal/tacacs/testclient.TestTLSForcesUnencryptedAndRejectsClearFlag |
| T98-ROLE-005 | CLIENT-ROLE MUST NOT | PASS | Test client sends no 0-RTT and includes no early-data extension | unit:internal/tacacs/testclient.TestDialTLSClientHelloHasNoEarlyData |
| T98-ROLE-006 | OPERATOR SHOULD | PASS | Production-like security tests run TLS-only or use separate hosts/instances for legacy and secure services | docs:deployments/compose/compose.tls-only.yaml; lab:tools/lab-test.sh TLS-only phase; docs:docs/OPERATOR.md |

## RFC 2865

RFC 2865 RADIUS

| ID | Level | Status | Requirement | Evidence |
|---|---|---|---|---|
| R65-PKT-001 | MUST | PASS | Enforce packet length/header bounds | unit:internal/radius/codec.TestDecodeHeaderTruncation; unit:internal/radius/codec.TestDecodeIgnoresTrailingPadding; unit:internal/radius/codec.TestDecodeRejectsDeclaredOverRFCMax; unit:internal/radius/codec.TestRadiusCatalog; unit:internal/radius/testclient/codec.TestIndependentCatalogBytes; unit:internal/radius/codec.TestPeerEncodeDecodeCatalogBytes; golden:testdata/protocol/radius/vectors.json; fuzz:internal/radius/codec.FuzzRadiusPacketDecode; bench:internal/radius/codec.BenchmarkRadiusPacketDecode_8Attrs |
| R65-PKT-002 | MUST | PASS | Handle supported/unsupported Codes deterministically | unit:internal/radius/codec.TestCodeClassification; unit:internal/radius/codec.TestDecodeUnknownCodePreserved; unit:internal/radius/codec.TestDecodeAccessChallenge; unit:internal/radius/udp.TestInvalidCodeAndShortDatagramDiscard; unit:internal/radius/server.TestStubDiscardsWrongCode; unit:internal/radius/testclient/codec.TestIndependentCatalogBytes; golden:testdata/protocol/radius/packets/access-challenge-min.bin |
| R65-ATTR-001 | MUST | PASS | Validate Type/Length/Value framing | unit:internal/radius/attribute.TestDecodeRejectsShortLength; unit:internal/radius/attribute.TestDecodeRejectsOverflow; unit:internal/radius/codec.TestDecodeAttributeOverflow; unit:internal/radius/testclient/codec.TestIndependentCatalogBytes; fuzz:internal/radius/attribute.FuzzRadiusAttributeDecode |
| R65-ATTR-002 | MUST | PASS | Preserve ordered duplicate attributes | unit:internal/radius/attribute.TestDecodePreservesOrderAndDuplicates; unit:internal/radius/codec.TestRoundTripWithAttributes; unit:internal/radius/codec.TestPeerConstructedPacketBytes; golden:testdata/protocol/radius/packets/access-request-dup-proxy-state.bin |
| R65-VSA-001 | MUST | PASS | Parse/encode VSA framing and preserve unknown vendor data safely | unit:internal/radius/attribute.TestParseVSARoundTrip; unit:internal/radius/attribute.TestParseVSAUnknownVendorPreserved; unit:internal/radius/attribute.TestPacketKeepsMalformedVSARaw; unit:internal/radius/codec.TestVSAGoldenFraming; unit:internal/radius/testclient/codec.TestIndependentVSAFraming; fuzz:internal/radius/attribute.FuzzRadiusVSA; golden:testdata/protocol/radius/packets/access-request-vsa.bin |
| R65-PROXY-001 | MUST | PASS | Preserve Proxy-State order/value in responses | unit:internal/radius/server.TestSignResponseMAFirstThenResponseAuthenticator; unit:internal/radius/server.TestAccessPermitEmitsAcceptWithProfileAttrs; golden:testdata/protocol/radius/packets/access-request-dup-proxy-state.bin |
| R65-RAUTH-001 | MUST | PASS | Validate/generate request and response authenticators | unit:internal/radius/crypto.TestNewRequestAuthenticatorIsNonce; unit:internal/radius/crypto.TestResponseAuthenticatorVectors; unit:internal/radius/testclient/codec.TestIndependentResponseAuthenticatorVectors; unit:internal/radius/crypto.TestPeerResponseAuthenticatorBytes; golden:testdata/protocol/radius/crypto/vectors.json; bench:internal/radius/crypto.BenchmarkResponseAuthenticator |
| R65-PAP-001 | MUST | PASS | Correct User-Password hide/unhide and block/length checks | unit:internal/radius/crypto.TestUserPasswordVectors; unit:internal/radius/crypto.TestHideUnhideRoundTrip; unit:internal/radius/crypto.TestCanaryUnhiddenPasswordNeverInErrors; unit:internal/radius/testclient/codec.TestIndependentUserPasswordVectors; unit:internal/radius/crypto.TestPeerUserPasswordHideBytes; golden:testdata/protocol/radius/crypto/vectors.json; fuzz:internal/radius/crypto.FuzzUnhideUserPassword; bench:internal/radius/crypto.BenchmarkUnhideUserPassword |
| R65-CHAP-001 | MUST | PASS | Validate CHAP evidence/challenge selection | unit:internal/radius/server.TestAccessCHAPUsesChallengeOrRequestAuthenticator; unit:internal/radius/server.TestAccessExtractRejects; unit:internal/radius/udp.TestUDPPAPAndCHAPRejectPaths |
| R65-ACCESS-001 | MUST | PASS | Parse and validate Access-Request | unit:internal/radius/server.TestAccessExtractRejects; unit:internal/radius/udp.TestUDPPAPAndCHAPRejectPaths; unit:internal/radius/testclient.TestEncodeAccessRequestRejectsConflict; unit:internal/aaa.TestAuthenticateAccessDefaultDenyAndRejects |
| R65-ACCESS-002 | MUST | PASS | Construct valid Access-Accept | unit:internal/radius/server.TestAccessPermitEmitsAcceptWithProfileAttrs; unit:internal/radius/udp.TestUDPPAPAcceptFromCompiledPolicy; unit:internal/radius/udp.TestIndependentTestclientPAPAndAccountingOnUDP; unit:internal/radius/testclient.TestAccessReplyRequiresMessageAuthenticator; interop:internal/radius/udp.TestIndependentTestclientPAPAndAccountingOnUDP |
| R65-ACCESS-003 | MUST | PASS | Construct valid Access-Reject | unit:internal/radius/server.TestAccessExtractRejects; unit:internal/radius/server.TestStubAccessRejectsAfterDecode; unit:internal/radius/testclient.TestAccessReplyRequiresMessageAuthenticator; unit:internal/aaa.TestAuthenticateAccessDefaultDenyAndRejects |
| R65-ACCESS-004 | MUST | DEFERRED_MAY | Access-Challenge only under complete state/security gate | adr:docs/decisions/0016-radius-udp-security-retransmission-and-scope.md |

## RFC 2866

RFC 2866 RADIUS Accounting

| ID | Level | Status | Requirement | Evidence |
|---|---|---|---|---|
| R66-PKT-001 | MUST | PASS | Validate Accounting-Request and its authenticator | unit:internal/radius/crypto.TestAccountingRequestAuthenticatorVectors; unit:internal/radius/crypto.TestAccountingAuthenticatorIgnoresOnWireField; unit:internal/radius/server.TestAccountingValidatesRequestAuthenticator; unit:internal/radius/testclient/codec.TestIndependentAccountingRequestAuthenticatorVectors; unit:internal/radius/crypto.TestPeerAccountingRequestAuthenticatorBytes; golden:testdata/protocol/radius/crypto/vectors.json; fuzz:internal/radius/crypto.FuzzAccountingRequestAuthenticator; bench:internal/radius/crypto.BenchmarkAccountingRequestAuthenticator |
| R66-RESP-001 | MUST | PASS | Construct exact Accounting-Response | unit:internal/radius/udp.TestAccountingResponseOnUDP; unit:internal/radius/server.TestAccountingFiveStatusTypes; unit:internal/radius/testclient.TestAccountingResponseRequiresMA; unit:internal/radius/udp.TestIndependentTestclientPAPAndAccountingOnUDP; interop:internal/radius/udp.TestIndependentTestclientPAPAndAccountingOnUDP |
| R66-STAT-001 | MUST | PASS | Map declared Acct-Status-Type values | unit:internal/radius/server.TestAccountingFiveStatusTypes; unit:internal/radius/server.TestAccountingUnknownAndAllowlistedStatus; unit:internal/aaa.TestRecordRADIUSAccountingAllKinds |

## RFC 2869

RFC 2869 RADIUS Extensions

| ID | Level | Status | Requirement | Evidence |
|---|---|---|---|---|
| R69-MA-001 | MUST | PASS | Validate Message-Authenticator on Access-Request whenever present | unit:internal/radius/crypto.TestMessageAuthenticatorVectors; unit:internal/radius/crypto.TestMessageAuthenticatorZerosValueDuringCompute; unit:internal/radius/crypto.TestValidateMessageAuthenticatorTamper; unit:internal/radius/server.TestCheckAccessIntegrityMAAndProxyState; unit:internal/radius/testclient/codec.TestIndependentMessageAuthenticatorVectors; unit:internal/radius/crypto.TestPeerMessageAuthenticatorBytes; golden:testdata/protocol/radius/crypto/vectors.json; fuzz:internal/radius/crypto.FuzzValidateMessageAuthenticator |
| R69-MA-002 | MUST | PASS | Insert Message-Authenticator on Access responses before Response Authenticator | unit:internal/radius/server.TestSignResponseMAFirstThenResponseAuthenticator; unit:internal/radius/testclient.TestAccessReplyRequiresMessageAuthenticator; unit:internal/radius/testclient.TestAccessReplyRejectsMAOverResponseAuthenticator; unit:internal/radius/udp.TestIndependentTestclientPAPAndAccountingOnUDP |
| R69-ACCT-002 | MUST | PASS | Interim accounting, gigaword counters, Event-Timestamp, and Acct-Interim-Interval | unit:internal/radius/server.TestAccountingInterimNotCollapsed; unit:internal/radius/server.TestAccountingGigawordFoldAndTerminateCause; unit:internal/radius/udp.TestAccountingExactRetryAndDelayTimeAndInterim; unit:internal/radius/server.TestAccountingJournalHitDoesNotRerecord |

## RFC 3579

RFC 3579 RADIUS Support For Extensible Authentication Protocol (EAP)

| ID | Level | Status | Requirement | Evidence |
|---|---|---|---|---|
| R79-MA-001 | MUST | PASS | Validate/calculate Message-Authenticator | unit:internal/radius/crypto.TestMessageAuthenticatorVectors; unit:internal/radius/crypto.TestMessageAuthenticatorMissingDuplicateWrongLength; unit:internal/radius/server.TestCheckAccessIntegrityMAAndProxyState; unit:internal/radius/server.TestSignResponseMAFirstThenResponseAuthenticator; unit:internal/radius/testclient/codec.TestIndependentMessageAuthenticatorVectors; unit:internal/radius/crypto.TestPeerMessageAuthenticatorBytes; golden:testdata/protocol/radius/crypto/vectors.json; bench:internal/radius/crypto.BenchmarkMessageAuthenticator |

## RFC 5080

RFC 5080 Common RADIUS Implementation Issues and Suggested Fixes

| ID | Level | Status | Requirement | Evidence |
|---|---|---|---|---|
| R80-DUP-001 | MUST | PASS | Duplicate/retransmission behavior is deterministic and bounded | unit:internal/radius/udp.TestCacheHitPendingPurge; unit:internal/radius/udp.TestAccessRejectAndCacheHitPendingPurgeOnUDP; unit:internal/radius/udp.TestUDPIntegrityDiscardsDoNotMutateCache; unit:internal/radius/udp.TestAccountingExactRetryAndDelayTimeAndInterim; bench:internal/radius/udp.BenchmarkRadiusRetransmissionCacheHit |

## Project RADIUS

Project RADIUS completeness

| ID | Level | Status | Requirement | Evidence |
|---|---|---|---|---|
| PRJ-SEC-001 | PROJECT MUST | PASS | Missing/invalid required Message-Authenticator silently discards with bounded diagnostics | unit:internal/radius/server.TestCheckAccessIntegrityMAAndProxyState; unit:internal/radius/udp.TestUDPIntegrityDiscardsDoNotMutateCache; unit:internal/radius/server.TestAccessDiscardsInvalidMA |
| PRJ-SEC-002 | PROJECT MUST | PASS | Unknown/ambiguous clients and invalid authenticators receive no useful response | unit:internal/radius/udp.TestUnknownClientDiscardUsesCompiledRADIUSIndex; unit:internal/radius/udp.TestUnknownAccountingClientUsesCompiledRADIUSIndex; unit:internal/radius/server.TestAccountingValidatesRequestAuthenticator; unit:internal/config.TestRADIUSIndexUnknownSource |
| PRJ-POL-001 | PROJECT MUST | PASS | Policy result is deterministic and reply attributes are role/type validated | unit:internal/policy/radius.TestEvaluateDefaultDenyUnknownClient; unit:internal/policy/radius.TestCompileRejectsIllegalReplyRole; unit:internal/policy/radius.TestGoldenTraces; unit:internal/radius/server.TestAccessIllegalAcceptAttrsFailClosed; unit:internal/aaa.TestAuthenticateAccessPermitFromCompiledPolicy; race:internal/policy/radius.TestEvaluateConcurrent |
| PRJ-POL-002 | PROJECT MUST | PASS | v2 users/groups attach radius_policy_id; evaluation is user then effectiveGroups then client then fallback then default deny | unit:internal/config.TestV2ParsesUserAndGroupRADIUSPolicyID; unit:internal/config.TestV2RejectsUnknownUserRADIUSPolicyID; unit:internal/policy/radius.TestEvaluateUserPolicyBeforeGroupAndClient; unit:internal/policy/radius.TestEvaluateGroupPriorityThenID; unit:internal/policy/radius.TestGoldenUserGroupTraces; unit:internal/aaa.TestAuthenticateAccessUserPolicyWinsBeforeClient; unit:internal/api/operations.TestUsersGroupsRADIUSPolicyIDCreateUpdateGetExport; unit:internal/api/parity.TestParityRequiredEquivalence; adr:docs/decisions/0029-user-group-radius-policy-attachment.md |
| PRJ-ERR-001 | PROJECT MUST | PASS | Discard/reject/internal/overload mapping is stable and non-oracular | unit:internal/radius/server.TestReasonTableStable; unit:internal/radius/server.TestAccessExtractRejects; unit:internal/radius/server.TestWireAccessReasonChallengeCodes; unit:internal/radius/server.TestAccessUnknownStateRejects; unit:internal/radius/udp.TestInvalidCodeAndShortDatagramDiscard |
| PRJ-ACCT-001 | PROJECT MUST | PASS | Retransmission replays exact response and emits one accounting event | unit:internal/radius/server.TestAccountingJournalHitDoesNotRerecord; unit:internal/radius/udp.TestAccountingExactRetryAndDelayTimeAndInterim; unit:internal/radius/server.TestAccountingInterimNotCollapsed |
| PRJ-ACCT-002 | PROJECT MUST | PASS | Accounting/event storage is bounded, redacted, and documented as memory-only | unit:internal/radius/udp.TestJournalSeenRememberExpirySaturation; unit:internal/radius/udp.TestJournalByteSaturation; unit:internal/radius/server.TestAccountingAmbiguousIdentitySampled; unit:internal/aaa.TestRecordRADIUSAccountingRedactsSensitiveAttributes; race:internal/aaa.TestRecordRADIUSAccountingRace |
| PRJ-RUN-001 | PROJECT MUST | PASS | Listener queues/workers/cache/state/output have hard limits and recover after overload | unit:internal/radius/udp.TestCacheAbandonAndExpiryAndSaturation; unit:internal/radius/udp.TestJournalSeenRememberExpirySaturation; unit:internal/radius/udp.TestSourceLimiterBurstThenRefill; unit:internal/radius/server.TestAccountingJournalSaturatedStillRecords; bench:internal/radius/udp.BenchmarkRadiusUDPDispatch_Parallel |
| PRJ-RUN-002 | PROJECT MUST | PASS | One datagram binds to one endpoint, secret handle, snapshot revision, and policy view | unit:internal/config.TestRADIUSIndexRoleSeparation; unit:internal/config.TestRADIUSIndexLongestPrefix; unit:internal/state.TestSnapshotCompilesRADIUSIndexes; unit:internal/radius/udp.TestUnknownClientDiscardUsesCompiledRADIUSIndex; bench:internal/state.BenchmarkRADIUSLookup_IPv4 |
| PRJ-CFG-001 | PROJECT MUST | PASS | Strict v1 migrates deterministically; strict v2 rejects unknown/mixed syntax | unit:internal/config.TestV1AndV2TACACSEquivalent; unit:internal/config.TestV1FixturesKeepTACACSAndDisableRADIUS; unit:internal/config.TestRejectFixtures; unit:internal/state.TestV1TACACSSnapshotEquivalent |
| PRJ-TAC-001 | PROJECT MUST | PASS | Existing TACACS legacy/TLS conformance remains green | unit:tools/registry.TestReleaseValidationPassesQualifiedRegistries; unit:tools/registry.TestReleaseGateExcludesRADIUSSkeletons; docs:docs/generated/conformance.md |
| PRJ-PAR-001 | PROJECT MUST | PASS | REST/MCP/UI generated parity remains green | unit:internal/api/parity.TestParityRequiredEquivalence; unit:internal/api/parity.TestEveryParityRequiredHasCase; unit:internal/api/operations.TestRadiusAccessTestPAPAcceptAndWipe; lab:LAB-RADIUS-002 |
| PRJ-UL-001 | PROJECT MUST | PASS | Access-Reject reject_password_change_required after good PAP/CHAP + must_change_login; no extra attributes; no Access-Challenge | unit:internal/aaa.TestAuthenticateAccessMustChangeRejectsWithoutPolicy; unit:internal/radius/server.TestReasonTableStable; docs:docs/designs/radius-authentication.md |
| PRJ-MSCHAP-001 | PROJECT MUST | PASS | RADIUS MS-CHAPv1/v2 via RFC 2548 vendor 311 VSAs with independent RADIUS wire vectors; must_change is Access-Reject with no MS-CHAP-Error | unit:internal/radius/attribute.TestParseVendorTLVsRoundTripAndUnknown; unit:internal/radius/attribute.TestNamedMicrosoftVSAs; unit:internal/credentials.TestGenerateMSCHAPv2SuccessRFC2759; unit:internal/radius/server.TestAccessExtractMSCHAPv1Maps50To49; unit:internal/radius/server.TestAccessMSCHAPConflictMatrix; unit:internal/aaa.TestAuthenticateAccessMSCHAPPermitAndMustChange; unit:internal/radius/testclient.TestIndependentMSCHAPVSAsRoundTrip; unit:internal/radius/udp.TestIndependentTestclientMSCHAPOnUDP; unit:internal/api/operations.TestRadiusAccessTestMSCHAPAndPolicyEvaluate; adr:docs/decisions/0023-radius-mschap-vsas.md; golden:testdata/protocol/radius/mschap/rfc2433-v1-radius.json; golden:testdata/protocol/radius/mschap/rfc2759-v2-radius.json |

