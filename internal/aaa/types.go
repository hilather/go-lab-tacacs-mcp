package aaa

import "github.com/hilather/go-lab-tacacs-mcp/internal/domain"

// AuthenticationStart is one authentication START in domain terms.
type AuthenticationStart struct {
	ConnKey   uint64
	SessionID uint32
	UserID    string
	ClientID  string
	Action    domain.AuthenAction
	Type      domain.AuthenType
	Service   domain.AuthenService
	PrivLvl   uint8
	Port      string
	Remote    string
	Data      []byte
	Revision  domain.Revision
	Transport domain.Transport
}

// AuthenticationContinue is one CONTINUE in domain terms.
type AuthenticationContinue struct {
	ConnKey   uint64
	SessionID uint32
	Abort     bool
	UserMsg   []byte
	ClientID  string
	Revision  domain.Revision
	Transport domain.Transport
}

// AuthenticationAbort is an explicit abort of an in-progress conversation.
type AuthenticationAbort struct {
	ConnKey   uint64
	SessionID uint32
	ClientID  string
	Revision  domain.Revision
}

// AuthenticationStep is the next prompt or terminal result.
type AuthenticationStep struct {
	Status    domain.AuthenStatus
	NoEcho    bool
	ServerMsg string
}

// AuthorizationRequest is protocol-independent authorization input.
// AuthenType and AuthenService are copied onto the trace only; they are
// never match keys (matchService / matchCommand use AV service/cmd).
type AuthorizationRequest struct {
	UserID        string
	ClientID      string
	Service       string
	Protocol      string
	Cmd           string
	CmdArgs       []string
	Arguments     domain.AVPairs
	AuthenMethod  domain.AuthenMethod
	AuthenType    domain.AuthenType
	AuthenService domain.AuthenService
	Privilege     domain.PrivilegeLevel
	Port          string
	Remote        string
	Revision      domain.Revision
	Transport     domain.Transport
	SessionID     uint32
}

// AuthorizationDecision is the evaluator result plus a redacted trace.
type AuthorizationDecision struct {
	Decision  domain.AuthorDecision
	Status    domain.AuthorStatus
	Arguments domain.AVPairs
	Trace     PolicyTrace
}

// PolicyTrace is the redacted explanation returned by explain and evaluate.
type PolicyTrace struct {
	Evaluator         string             `json:"evaluator"`
	UserID            string             `json:"user_id"`
	ClientID          string             `json:"client_id"`
	Service           string             `json:"service"`
	Protocol          string             `json:"protocol"`
	Cmd               string             `json:"cmd"`
	CmdArgs           []string           `json:"cmd_args"`
	DisplayCmd        string             `json:"display_cmd"`
	RequestArguments  []PolicyTraceAV    `json:"request_arguments"`
	AuthenMethod      string             `json:"authen_method"`
	AuthenType        string             `json:"authen_type,omitempty"`
	AuthenService     string             `json:"authen_service,omitempty"`
	Privilege         uint8              `json:"privilege"`
	Port              string             `json:"port,omitempty"`
	Remote            string             `json:"remote,omitempty"`
	EffectiveGroupIDs []string           `json:"effective_group_ids"`
	Steps             []PolicyTraceStep  `json:"steps"`
	Winner            *PolicyTraceWinner `json:"winner"`
	Decision          string             `json:"decision"`
	Status            string             `json:"status"`
	Arguments         []PolicyTraceAV    `json:"arguments"`
	DefaultDeny       string             `json:"default_deny,omitempty"`
	Error             string             `json:"error,omitempty"`
}

// PolicyTraceStep is one considered rule.
type PolicyTraceStep struct {
	Source  string `json:"source"`
	RuleID  string `json:"rule_id"`
	Kind    string `json:"kind"`
	Matched bool   `json:"matched"`
	Reason  string `json:"reason"`
}

// PolicyTraceWinner names the first matching rule.
type PolicyTraceWinner struct {
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
	Action string `json:"action"`
}

// PolicyTraceAV is a stable AV encoding.
type PolicyTraceAV struct {
	Name      string `json:"name"`
	Separator string `json:"separator"`
	Value     string `json:"value"`
}

// AccountingRecord is one accounting request in domain terms.
type AccountingRecord struct {
	Flags        byte
	UserID       string
	ClientID     string
	SessionID    uint32
	Arguments    domain.AVPairs
	Revision     domain.Revision
	Transport    domain.Transport
	Port         string
	Remote       string
	AuthenMethod domain.AuthenMethod
	Privilege    domain.PrivilegeLevel
	AuthenType   domain.AuthenType
	Service      domain.AuthenService
}

// AccountingResult is the sink acknowledgement.
type AccountingResult struct {
	OK      bool
	EventID uint64
}

// Accounting flag bits (RFC 8907). Duplicated here so AAA does not import codec.
const (
	AcctFlagStart          byte = 0x02
	AcctFlagStop           byte = 0x04
	AcctFlagWatchdog       byte = 0x08
	AcctFlagWatchdogUpdate byte = 0x0a
)

// ValidAcctFlags reports whether flags are a defined combination.
func ValidAcctFlags(flags byte) bool {
	switch flags {
	case AcctFlagStart, AcctFlagStop, AcctFlagWatchdog, AcctFlagWatchdogUpdate:
		return true
	default:
		return false
	}
}
