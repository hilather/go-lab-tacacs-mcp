package policy

import "github.com/hilather/go-lab-tacacs-mcp/internal/domain"

// buildReply copies rule attributes in order. deny yields no arguments.
// Limits apply to the response list; overflow is a processing error, not deny.
func buildReply(action domain.AuthorDecision, reply domain.AVPairs, lim limits) (domain.AVPairs, error) {
	if action == domain.DecisionDeny || len(reply) == 0 {
		return domain.AVPairs{}, nil
	}
	if lim.maxArgs > 0 && len(reply) > lim.maxArgs {
		return nil, domain.NewError(domain.CodeInvalidArgument, "authorization response exceeds max_authorization_arguments")
	}
	out := make(domain.AVPairs, 0, len(reply))
	for _, p := range reply {
		if err := p.Validate(); err != nil {
			return nil, err
		}
		if lim.maxArgBytes > 0 && p.EncodedLen() > lim.maxArgBytes {
			return nil, domain.NewError(domain.CodeInvalidArgument, "authorization argument exceeds max_argument_bytes")
		}
		out = append(out, p)
	}
	return out, nil
}

func finish(tr Trace, action domain.AuthorDecision, reply domain.AVPairs, lim limits) Result {
	status := action.WireStatus()
	avs, err := buildReply(action, reply, lim)
	if err != nil {
		return errorResult(tr, err.Error())
	}
	tr.Decision = action.String()
	tr.Status = status.String()
	tr.Arguments = traceAVs(avs)
	if tr.Steps == nil {
		tr.Steps = []TraceStep{}
	}
	if tr.EffectiveGroupIDs == nil {
		tr.EffectiveGroupIDs = []string{}
	}
	if tr.CmdArgs == nil {
		tr.CmdArgs = []string{}
	}
	return Result{Decision: action, Status: status, Arguments: avs, Trace: tr}
}

func denyResult(tr Trace, reason string) Result {
	tr.DefaultDeny = reason
	tr.Winner = nil
	return finish(tr, domain.DecisionDeny, nil, limits{})
}

func errorResult(tr Trace, reason string) Result {
	tr.DefaultDeny = ""
	tr.Error = reason
	tr.Winner = nil
	tr.Decision = ""
	tr.Status = domain.AuthorStatusError.String()
	tr.Arguments = []TraceAV{}
	if tr.Steps == nil {
		tr.Steps = []TraceStep{}
	}
	if tr.EffectiveGroupIDs == nil {
		tr.EffectiveGroupIDs = []string{}
	}
	if tr.CmdArgs == nil {
		tr.CmdArgs = []string{}
	}
	return Result{
		Decision:  "",
		Status:    domain.AuthorStatusError,
		Arguments: domain.AVPairs{},
		Trace:     tr,
	}
}

func matchedResult(tr Trace, source, ruleID string, action domain.AuthorDecision, reply domain.AVPairs, lim limits) Result {
	tr.Winner = &TraceWinner{Source: source, RuleID: ruleID, Action: action.String()}
	tr.DefaultDeny = ""
	return finish(tr, action, reply, lim)
}
