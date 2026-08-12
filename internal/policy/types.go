package policy

import (
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Request is protocol-independent authorization input.
//
// AuthenMethod is retained for traces and is never a match predicate.
// Cmd empty or absent selects EvaluateService; a non-empty Cmd selects
// EvaluateCommand.
type Request struct {
	UserID       string
	ClientID     string
	Service      string
	Protocol     string
	Cmd          string
	CmdArgs      []string
	Arguments    domain.AVPairs
	AuthenMethod domain.AuthenType
	Privilege    domain.PrivilegeLevel
	Port         string
	RemoteAddr   string
}

// Result is the evaluator output. FOLLOW is never set.
type Result struct {
	Decision  domain.AuthorDecision
	Status    domain.AuthorStatus
	Arguments domain.AVPairs
	Trace     Trace
}

// Trace is a deterministic explanation of one evaluation.
type Trace struct {
	Evaluator         string       `json:"evaluator"`
	UserID            string       `json:"user_id"`
	ClientID          string       `json:"client_id"`
	Service           string       `json:"service"`
	Protocol          string       `json:"protocol"`
	Cmd               string       `json:"cmd"`
	CmdArgs           []string     `json:"cmd_args"`
	DisplayCmd        string       `json:"display_cmd"`
	RequestArguments  []TraceAV    `json:"request_arguments"`
	AuthenMethod      string       `json:"authen_method"`
	Privilege         uint8        `json:"privilege"`
	EffectiveGroupIDs []string     `json:"effective_group_ids"`
	Steps             []TraceStep  `json:"steps"`
	Winner            *TraceWinner `json:"winner"`
	Decision          string       `json:"decision"`
	Status            string       `json:"status"`
	Arguments         []TraceAV    `json:"arguments"`
	DefaultDeny       string       `json:"default_deny,omitempty"`
	Error             string       `json:"error,omitempty"`
}

// TraceStep is one considered rule.
type TraceStep struct {
	Source  string `json:"source"`
	RuleID  string `json:"rule_id"`
	Kind    string `json:"kind"`
	Matched bool   `json:"matched"`
	Reason  string `json:"reason"`
}

// TraceWinner names the first matching rule.
type TraceWinner struct {
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
	Action string `json:"action"`
}

// TraceAV is a stable AV encoding for traces and goldens.
type TraceAV struct {
	Name      string `json:"name"`
	Separator string `json:"separator"`
	Value     string `json:"value"`
}

func displayCommand(cmd string, args []string) string {
	if cmd == "" {
		return strings.Join(args, " ")
	}
	if len(args) == 0 {
		return cmd
	}
	return cmd + " " + strings.Join(args, " ")
}

func joinArgs(args []string) string {
	return strings.Join(args, " ")
}

func traceAVs(in domain.AVPairs) []TraceAV {
	if in == nil {
		return []TraceAV{}
	}
	out := make([]TraceAV, len(in))
	for i, p := range in {
		out[i] = TraceAV{Name: p.Name, Separator: string([]byte{p.Separator}), Value: p.Value}
	}
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
