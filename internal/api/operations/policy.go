package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
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
	tr, _, err := aaa.Evaluate(eng, toAuthorizationRequest(req))
	if err != nil {
		return nil, err
	}
	return policyTraceFromAAA(tr), nil
}

func toAuthorizationRequest(req EvaluatePolicyRequest) aaa.AuthorizationRequest {
	out := aaa.AuthorizationRequest{
		UserID:    req.UserID,
		ClientID:  req.ClientID,
		Service:   req.Service,
		Protocol:  req.Protocol,
		Cmd:       req.Cmd,
		CmdArgs:   req.CmdArgs,
		Arguments: avsFromTrace(req.Arguments),
		Port:      req.Port,
		Remote:    req.Remote,
	}
	if req.AuthenMethod != "" {
		if m, err := domain.ParseAuthenMethod(req.AuthenMethod); err == nil {
			out.AuthenMethod = m
		}
	}
	if req.AuthenType != "" {
		if t, err := domain.ParseAuthenType(req.AuthenType); err == nil {
			out.AuthenType = t
		}
	}
	if req.AuthenService != "" {
		if s, err := domain.ParseAuthenService(req.AuthenService); err == nil {
			out.AuthenService = s
		}
	}
	if p, err := domain.ParsePrivilegeLevel(int(req.Privilege)); err == nil {
		out.Privilege = p
	}
	return out
}

func avsFromTrace(in []PolicyTraceAV) domain.AVPairs {
	if len(in) == 0 {
		return nil
	}
	out := make(domain.AVPairs, 0, len(in))
	for _, a := range in {
		sep := domain.AVSepMandatory
		if a.Separator != "" {
			sep = a.Separator[0]
		}
		out = append(out, domain.AVPair{Name: a.Name, Separator: sep, Value: a.Value})
	}
	return out
}

func policyTraceFromAAA(in aaa.PolicyTrace) PolicyTrace {
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
		AuthenType:        in.AuthenType,
		AuthenService:     in.AuthenService,
		Privilege:         in.Privilege,
		Port:              in.Port,
		Remote:            in.Remote,
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
	out.RequestArguments = copyOpAVs(in.RequestArguments)
	out.Arguments = copyOpAVs(in.Arguments)
	return out
}

func copyOpAVs(in []aaa.PolicyTraceAV) []PolicyTraceAV {
	out := make([]PolicyTraceAV, len(in))
	for i, a := range in {
		out[i] = PolicyTraceAV{Name: a.Name, Separator: a.Separator, Value: a.Value}
	}
	return out
}
