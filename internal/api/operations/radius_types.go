package operations

import "github.com/hilather/go-lab-tacacs-mcp/internal/aaa"

// RADIUS wire outcome strings returned by radius.access.test.
// They are not domain.AuthOutcome and not advertised as complete RADIUS.
const (
	RadiusOutcomeAccept    = "access_accept"
	RadiusOutcomeReject    = "access_reject"
	RadiusOutcomeChallenge = "access_challenge"
)

// RadiusAccessTestOutcomes is the closed set of radius.access.test outcome values.
var RadiusAccessTestOutcomes = []string{
	RadiusOutcomeAccept,
	RadiusOutcomeReject,
	RadiusOutcomeChallenge,
}

// RadiusAuthMethodTypes is the closed method.type union for diagnostics.
// eap and mschapv1/mschapv2 are opt-in on the wire; omitted lists stay [pap, chap].
var RadiusAuthMethodTypes = []string{"pap", "chap", "mschapv1", "mschapv2", "eap"}

// RadiusAccessTestRequest simulates one Access-Request without UDP.
// Method.Password, Challenge, and Response are write-only and wiped.
type RadiusAccessTestRequest struct {
	ClientID          string                 `json:"client_id,omitempty"`
	UserID            string                 `json:"user_id"`
	Method            RadiusAuthMethod       `json:"method"`
	RequestAttributes []RadiusAttributeValue `json:"request_attributes,omitempty"`
	Explain           bool                   `json:"explain,omitempty"`
}

// RadiusAuthMethod is the RADIUS diagnostic method tagged union.
// type is pap, chap, mschapv1, mschapv2, or eap (RADIUS names). pap maps to domain.AuthMethodPassword.
// EAP without challenge/response is Identity start (access_challenge).
// EAP with challenge+response is one-shot EAP-MD5 (CHAP-equivalent).
type RadiusAuthMethod struct {
	Type      string `json:"type"`
	Password  string `json:"password,omitempty"`
	ID        uint8  `json:"id,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	Response  string `json:"response,omitempty"`
}

// RadiusAttributeValue is a secret-free named or vendor+code attribute.
// Secret kinds are rejected on input. Reply values are never hidden material.
type RadiusAttributeValue struct {
	Name     string `json:"name,omitempty"`
	Vendor   uint32 `json:"vendor,omitempty"`
	Code     uint8  `json:"code,omitempty"`
	Value    string `json:"value,omitempty"`
	ValueHex string `json:"value_hex,omitempty"`
}

// RadiusAccessTestResult is the redacted Access-Accept/Reject/Challenge decision.
// StatePresent is true only on access_challenge. Raw State and EAP payloads
// are never included.
type RadiusAccessTestResult struct {
	Outcome         string                 `json:"outcome"`
	ReasonCode      string                 `json:"reason_code"`
	StatePresent    bool                   `json:"state_present,omitempty"`
	ReplyAttributes []RadiusAttributeValue `json:"reply_attributes"`
	Trace           *RadiusPolicyTrace     `json:"trace,omitempty"`
}

// RadiusAccessTestReasonCodes is the closed set of radius.access.test reason_code
// values (design §5.7 access replies plus Challenge/EAP codes).
var RadiusAccessTestReasonCodes = []string{
	aaa.AccessReasonOK,
	aaa.AccessReasonBadCredentials,
	aaa.AccessReasonPolicy,
	aaa.AccessReasonUnsupportedMethod,
	aaa.AccessReasonInternal,
	aaa.AccessReasonPasswordChangeRequired,
	aaa.AccessReasonChallenge,
	aaa.AccessReasonInvalidState,
	aaa.AccessReasonChallengeExpired,
	aaa.AccessReasonChallengeBinding,
	aaa.AccessReasonChallengeCapacity,
	aaa.AccessReasonUnsupportedEAPMethod,
	aaa.AccessReasonEAPTooLong,
}

// RadiusPolicyEvaluateRequest explains the compiled RADIUS engine.
// Method is pap, chap, mschapv1, mschapv2, or eap. Credentials are not verified.
type RadiusPolicyEvaluateRequest struct {
	ClientID          string                 `json:"client_id,omitempty"`
	UserID            string                 `json:"user_id"`
	Method            string                 `json:"method,omitempty"`
	EndpointID        string                 `json:"endpoint_id,omitempty"`
	RequestAttributes []RadiusAttributeValue `json:"request_attributes,omitempty"`
}

// RadiusPolicyEvaluateResult is the secret-free RADIUS policy explanation.
type RadiusPolicyEvaluateResult struct {
	Effect          string                 `json:"effect"`
	ReasonCode      string                 `json:"reason_code"`
	ReplyAttributes []RadiusAttributeValue `json:"reply_attributes"`
	Trace           RadiusPolicyTrace      `json:"trace"`
}

// RadiusPolicyTrace is a redacted RADIUS access-policy explanation.
type RadiusPolicyTrace struct {
	Evaluator   string                   `json:"evaluator"`
	UserID      string                   `json:"user_id"`
	ClientID    string                   `json:"client_id"`
	EndpointID  string                   `json:"endpoint_id,omitempty"`
	Method      string                   `json:"method,omitempty"`
	Groups      []string                 `json:"groups,omitempty"`
	Steps       []RadiusPolicyTraceStep  `json:"steps"`
	Winner      *RadiusPolicyTraceWinner `json:"winner,omitempty"`
	Effect      string                   `json:"effect,omitempty"`
	DefaultDeny string                   `json:"default_deny,omitempty"`
	Error       string                   `json:"error,omitempty"`
}

// RadiusPolicyTraceStep is one considered RADIUS rule.
type RadiusPolicyTraceStep struct {
	Source  string `json:"source"`
	RuleID  string `json:"rule_id"`
	Matched bool   `json:"matched"`
	Reason  string `json:"reason"`
}

// RadiusPolicyTraceWinner names the first matching RADIUS rule.
type RadiusPolicyTraceWinner struct {
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
	Effect string `json:"effect"`
}

// ListRadiusAttributesRequest is the empty input for radius.attributes.list.
type ListRadiusAttributesRequest struct{}

// RadiusAttributeList is the built-in dictionary metadata. No values.
type RadiusAttributeList struct {
	Version string                    `json:"version"`
	Items   []RadiusAttributeMetadata `json:"items"`
}

// RadiusAttributeMetadata is one dictionary entry. Sensitivity is metadata only.
// Source is "builtin" or "operator:<id>". Values are never included.
type RadiusAttributeMetadata struct {
	Name        string   `json:"name"`
	Code        uint8    `json:"code"`
	Vendor      uint32   `json:"vendor"`
	ValueKind   string   `json:"value_kind"`
	AllowedIn   []string `json:"allowed_in"`
	Sensitivity string   `json:"sensitivity"`
	Source      string   `json:"source"`
}

// ListRadiusSessionsRequest is a cursor page of in-memory RADIUS sessions.
type ListRadiusSessionsRequest struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// RadiusSessionList is sessions.list output in handle order.
type RadiusSessionList struct {
	Items      []RadiusSessionView `json:"items"`
	NextCursor *string             `json:"next_cursor"`
}

// RadiusSessionView is one index row. acct_session_id is events:sensitive.
type RadiusSessionView struct {
	SessionHandle string `json:"session_handle"`
	ClientID      string `json:"client_id,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	EndpointID    string `json:"endpoint_id,omitempty"`
	NASIP         string `json:"nas_ip,omitempty"`
	NASIdentifier string `json:"nas_identifier,omitempty"`
	NASPort       uint32 `json:"nas_port,omitempty"`
	Peer          string `json:"peer,omitempty"`
	StartedAt     string `json:"started_at,omitempty"`
	LastUpdate    string `json:"last_update,omitempty"`
	AcctSessionID string `json:"acct_session_id,omitempty"`
}

// RadiusDynamicAuthRequest is one DAC originate shape. Exactly one of handle
// or explicit (client_id) must be set. expected_revision is not a field.
type RadiusDynamicAuthRequest struct {
	SessionHandle string                 `json:"session_handle,omitempty"`
	ClientID      string                 `json:"client_id,omitempty"`
	Destination   string                 `json:"destination,omitempty"`
	UserID        string                 `json:"user_id,omitempty"`
	AcctSessionID string                 `json:"acct_session_id,omitempty"`
	Attributes    []RadiusAttributeValue `json:"attributes,omitempty"`
}

// RadiusDynamicAuthResult is ack, nak, or timeout. Timeout is not an overlay error.
type RadiusDynamicAuthResult struct {
	Outcome    string `json:"outcome"`
	ErrorCause uint32 `json:"error_cause,omitempty"`
}
