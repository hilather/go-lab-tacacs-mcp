package aaa

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/policy"
)

// Authorize evaluates session/service or command authorization.
func (s *Service) Authorize(ctx context.Context, req AuthorizationRequest) (AuthorizationDecision, error) {
	if err := ctx.Err(); err != nil {
		return errorDecision("context canceled"), err
	}
	tr, res, err := s.evaluate(req)
	if err != nil {
		return errorDecision(err.Error()), nil
	}
	s.record(events.Event{
		Category:  "author",
		Type:      tr.Evaluator,
		Result:    tr.Decision,
		Transport: string(req.Transport),
		ClientID:  req.ClientID,
		SessionID: req.SessionID,
		Revision:  req.Revision,
		UserID:    req.UserID,
		Command:   tr.DisplayCmd,
	}, redactUserInput(s.snap()))
	return AuthorizationDecision{
		Decision:  res.Decision,
		Status:    res.Status,
		Arguments: res.Arguments,
		Trace:     tr,
	}, nil
}

// ExplainAuthorization returns the redacted full trace without recording
// a protocol authorization event.
func (s *Service) ExplainAuthorization(ctx context.Context, req AuthorizationRequest) (PolicyTrace, error) {
	if err := ctx.Err(); err != nil {
		return PolicyTrace{}, err
	}
	tr, _, err := s.evaluate(req)
	return tr, err
}

func (s *Service) evaluate(req AuthorizationRequest) (PolicyTrace, policy.Result, error) {
	if s == nil {
		return PolicyTrace{Error: "aaa service is not initialized", Status: domain.AuthorStatusError.String()}, policy.Result{Status: domain.AuthorStatusError}, domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	snap := s.snap()
	eng, err := s.engine(snap)
	if err != nil {
		return PolicyTrace{Error: err.Error(), Status: domain.AuthorStatusError.String()}, policy.Result{Status: domain.AuthorStatusError}, err
	}
	return Evaluate(eng, req)
}

// Evaluate is the single two-evaluator walk used by live AUTHOR packets
// and policy.evaluate. It does not record events.
func Evaluate(eng *policy.Engine, req AuthorizationRequest) (PolicyTrace, policy.Result, error) {
	if eng == nil {
		return PolicyTrace{Error: "policy engine is not compiled", Status: domain.AuthorStatusError.String()}, policy.Result{Status: domain.AuthorStatusError}, domain.NewError(domain.CodeInternal, "policy engine is not compiled")
	}
	res := eng.Authorize(toPolicyRequest(req))
	return finishTrace(req, res), res, nil
}

func toPolicyRequest(req AuthorizationRequest) policy.Request {
	return policy.Request{
		UserID:       req.UserID,
		ClientID:     req.ClientID,
		Service:      req.Service,
		Protocol:     req.Protocol,
		Cmd:          req.Cmd,
		CmdArgs:      req.CmdArgs,
		Arguments:    req.Arguments,
		AuthenMethod: req.AuthenMethod,
		Privilege:    req.Privilege,
		Port:         req.Port,
		RemoteAddr:   req.Remote,
	}
}

func finishTrace(req AuthorizationRequest, res policy.Result) PolicyTrace {
	tr := copyTrace(res.Trace)
	tr.Port = req.Port
	tr.Remote = req.Remote
	tr.AuthenType = req.AuthenType.String()
	tr.AuthenService = req.AuthenService.String()
	return redactTrace(tr)
}

func errorDecision(reason string) AuthorizationDecision {
	return AuthorizationDecision{
		Status: domain.AuthorStatusError,
		Trace:  PolicyTrace{Error: reason, Status: domain.AuthorStatusError.String()},
	}
}

func copyTrace(in policy.Trace) PolicyTrace {
	out := PolicyTrace{
		Evaluator:         in.Evaluator,
		UserID:            in.UserID,
		ClientID:          in.ClientID,
		Service:           in.Service,
		Protocol:          in.Protocol,
		Cmd:               in.Cmd,
		CmdArgs:           append([]string(nil), in.CmdArgs...),
		DisplayCmd:        in.DisplayCmd,
		AuthenMethod:      in.AuthenMethod,
		Privilege:         in.Privilege,
		EffectiveGroupIDs: append([]string(nil), in.EffectiveGroupIDs...),
		Decision:          in.Decision,
		Status:            in.Status,
		DefaultDeny:       in.DefaultDeny,
		Error:             in.Error,
	}
	if in.Winner != nil {
		w := PolicyTraceWinner{Source: in.Winner.Source, RuleID: in.Winner.RuleID, Action: in.Winner.Action}
		out.Winner = &w
	}
	out.Steps = make([]PolicyTraceStep, len(in.Steps))
	for i, st := range in.Steps {
		out.Steps[i] = PolicyTraceStep{Source: st.Source, RuleID: st.RuleID, Kind: st.Kind, Matched: st.Matched, Reason: st.Reason}
	}
	out.RequestArguments = copyTraceAVs(in.RequestArguments)
	out.Arguments = copyTraceAVs(in.Arguments)
	return out
}

func copyTraceAVs(in []policy.TraceAV) []PolicyTraceAV {
	out := make([]PolicyTraceAV, len(in))
	for i, a := range in {
		out[i] = PolicyTraceAV{Name: a.Name, Separator: a.Separator, Value: a.Value}
	}
	return out
}

func redactTrace(tr PolicyTrace) PolicyTrace {
	tr.RequestArguments = redactTraceAVs(tr.RequestArguments)
	tr.Arguments = redactTraceAVs(tr.Arguments)
	return tr
}

func redactTraceAVs(in []PolicyTraceAV) []PolicyTraceAV {
	if in == nil {
		return []PolicyTraceAV{}
	}
	out := make([]PolicyTraceAV, len(in))
	for i, a := range in {
		out[i] = a
		if sensitiveAVName(a.Name) {
			out[i].Value = "[redacted]"
		}
	}
	return out
}

func sensitiveAVName(name string) bool {
	n := strings.ToLower(name)
	switch {
	case n == "password", n == "passwd", n == "secret", n == "key":
		return true
	case strings.Contains(n, "password"), strings.Contains(n, "secret"):
		return true
	default:
		return false
	}
}
