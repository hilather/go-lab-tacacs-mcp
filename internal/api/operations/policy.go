package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/policy"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleEvaluate(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(EvaluatePolicyRequest)
	if req.UserID == "" {
		return nil, domain.NewError(domain.CodeInvalidArgument, "user_id is required")
	}
	eng, err := aaa.CompileSnapshot(snap)
	if err != nil {
		return nil, err
	}
	res := eng.Authorize(policy.Request{
		UserID:   req.UserID,
		ClientID: req.ClientID,
		Service:  req.Service,
		Protocol: req.Protocol,
		Cmd:      req.Cmd,
		CmdArgs:  req.CmdArgs,
	})
	return policyTraceFrom(res.Trace), nil
}

func policyTraceFrom(in policy.Trace) PolicyTrace {
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
	out.RequestArguments = make([]PolicyTraceAV, len(in.RequestArguments))
	for i, a := range in.RequestArguments {
		out.RequestArguments[i] = PolicyTraceAV{Name: a.Name, Separator: a.Separator, Value: a.Value}
	}
	out.Arguments = make([]PolicyTraceAV, len(in.Arguments))
	for i, a := range in.Arguments {
		out.Arguments[i] = PolicyTraceAV{Name: a.Name, Separator: a.Separator, Value: a.Value}
	}
	return out
}
