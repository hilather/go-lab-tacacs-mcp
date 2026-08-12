package aaa

import (
	"context"

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
	res := eng.Authorize(policy.Request{
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
	})
	return copyTrace(res.Trace), res, nil
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
