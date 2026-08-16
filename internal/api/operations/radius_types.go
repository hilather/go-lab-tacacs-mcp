package operations

import "github.com/hilather/go-lab-tacacs-mcp/internal/aaa"

// RADIUS wire outcome strings returned by radius.access.test.
// They are not domain.AuthOutcome and not advertised as complete RADIUS.
const (
	RadiusOutcomeAccept = "access_accept"
	RadiusOutcomeReject = "access_reject"
)

// RadiusAccessTestRequest simulates one Access-Request without UDP.
// Method.Password is write-only and wiped after AuthenticateAccess.
type RadiusAccessTestRequest struct {
	ClientID          string                 `json:"client_id,omitempty"`
	UserID            string                 `json:"user_id"`
	Method            RadiusAuthMethod       `json:"method"`
	RequestAttributes []RadiusAttributeValue `json:"request_attributes,omitempty"`
	Explain           bool                   `json:"explain,omitempty"`
}

// RadiusAuthMethod is the RADIUS diagnostic method tagged union.
// type is pap or chap (RADIUS names). pap maps to domain.AuthMethodPassword.
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

// RadiusAccessTestResult is the redacted Access-Accept/Reject decision.
type RadiusAccessTestResult struct {
	Outcome         string                 `json:"outcome"`
	ReasonCode      string                 `json:"reason_code"`
	ReplyAttributes []RadiusAttributeValue `json:"reply_attributes"`
	Trace           *RadiusPolicyTrace     `json:"trace,omitempty"`
}

// RadiusAccessTestReasonCodes is the closed set of radius.access.test reason_code
// values returned by AuthenticateAccess (design §5.7 access replies).
var RadiusAccessTestReasonCodes = []string{
	aaa.AccessReasonOK,
	aaa.AccessReasonBadCredentials,
	aaa.AccessReasonPolicy,
	aaa.AccessReasonUnsupportedMethod,
	aaa.AccessReasonInternal,
	aaa.AccessReasonPasswordChangeRequired,
}

// RadiusPolicyEvaluateRequest explains the compiled RADIUS engine.
// Method is pap or chap. Credentials are not verified.
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
type RadiusAttributeMetadata struct {
	Name        string   `json:"name"`
	Code        uint8    `json:"code"`
	Vendor      uint32   `json:"vendor"`
	ValueKind   string   `json:"value_kind"`
	AllowedIn   []string `json:"allowed_in"`
	Sensitivity string   `json:"sensitivity"`
}
