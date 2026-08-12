package policy

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const (
	sourceUser     = "user"
	sourceGroup    = "group:"
	sourceFallback = "fallback"
)

// Authorize dispatches on cmd: empty/absent → service, non-empty → command.
func (e *Engine) Authorize(req Request) Result {
	if e == nil {
		return errorResult(Trace{}, "policy engine is not compiled")
	}
	req = e.normalize(req)
	if commandKey(req) != "" {
		return e.evaluate(req, domain.RuleKindCommand)
	}
	return e.evaluate(req, domain.RuleKindService)
}

// EvaluateService walks Kind=service rules only. A non-empty cmd is denied
// without consulting service permits.
func (e *Engine) EvaluateService(req Request) Result {
	if e == nil {
		return errorResult(Trace{}, "policy engine is not compiled")
	}
	req = e.normalize(req)
	if commandKey(req) != "" {
		tr := e.newTrace(domain.RuleKindService, req, nil)
		return denyResult(tr, "service evaluator does not authorize commands")
	}
	return e.evaluate(req, domain.RuleKindService)
}

// EvaluateCommand walks Kind=command rules only. An empty cmd is denied
// without consulting command rules.
func (e *Engine) EvaluateCommand(req Request) Result {
	if e == nil {
		return errorResult(Trace{}, "policy engine is not compiled")
	}
	req = e.normalize(req)
	if commandKey(req) == "" {
		tr := e.newTrace(domain.RuleKindCommand, req, nil)
		return denyResult(tr, "command evaluator does not decide session requests")
	}
	return e.evaluate(req, domain.RuleKindCommand)
}

func (e *Engine) evaluate(req Request, kind domain.RuleKind) Result {
	u, ok := e.users[req.UserID]
	groups := []compiledGroup{}
	if ok && u.enabled {
		groups = e.effectiveGroups(u, req.ClientID)
	}
	tr := e.newTrace(kind, req, groups)
	if !ok {
		return denyResult(tr, "user not found")
	}
	if !u.enabled {
		return denyResult(tr, "user disabled")
	}
	if !e.userValid(u) {
		return denyResult(tr, "user not valid at evaluation time")
	}
	if !clientAllowed(u, req.ClientID) {
		return denyResult(tr, "user not permitted on client")
	}

	if res, done := e.walkRules(sourceUser, u.rules, req, kind, &tr); done {
		return res
	}
	for _, g := range groups {
		if res, done := e.walkRules(sourceGroup+g.id, g.rules, req, kind, &tr); done {
			return res
		}
	}
	if res, done := e.walkRules(sourceFallback, e.fallback, req, kind, &tr); done {
		return res
	}
	return denyResult(tr, "no matching "+string(kind)+" rule")
}

func (e *Engine) walkRules(source string, rs compiledRuleSet, req Request, kind domain.RuleKind, tr *Trace) (Result, bool) {
	switch kind {
	case domain.RuleKindService:
		for _, r := range rs.services {
			matched, reason := matchService(r, req)
			e.record(tr, TraceStep{
				Source:  source,
				RuleID:  r.id,
				Kind:    string(domain.RuleKindService),
				Matched: matched,
				Reason:  reason,
			})
			if matched {
				return matchedResult(*tr, source, r.id, r.action, r.reply, e.limits), true
			}
		}
	case domain.RuleKindCommand:
		for _, r := range rs.commands {
			matched, reason := matchCommand(r, req)
			if matched && r.reason != "" {
				reason = r.reason
			}
			e.record(tr, TraceStep{
				Source:  source,
				RuleID:  r.id,
				Kind:    string(domain.RuleKindCommand),
				Matched: matched,
				Reason:  reason,
			})
			if matched {
				return matchedResult(*tr, source, r.id, r.action, nil, e.limits), true
			}
		}
	}
	return Result{}, false
}

func matchService(r compiledService, req Request) (bool, string) {
	if r.service != req.Service {
		return false, "service mismatch"
	}
	if r.protocol != nil && *r.protocol != "" && *r.protocol != req.Protocol {
		return false, "protocol mismatch"
	}
	return true, "matched"
}

func matchCommand(r compiledCommand, req Request) (bool, string) {
	if !r.command.match(req.Cmd) {
		return false, "command mismatch"
	}
	if !r.args.match(joinArgs(req.CmdArgs)) {
		return false, "arguments mismatch"
	}
	return true, "matched"
}

func (e *Engine) record(tr *Trace, step TraceStep) {
	if len(tr.Steps) >= e.limits.maxTraceSteps {
		return
	}
	tr.Steps = append(tr.Steps, step)
}

func (e *Engine) newTrace(kind domain.RuleKind, req Request, groups []compiledGroup) Trace {
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.id)
	}
	cmdArgs := cloneStrings(req.CmdArgs)
	display := displayCommand(req.Cmd, req.CmdArgs)
	if e.limits.maxCmdBytes > 0 && len(display) > e.limits.maxCmdBytes {
		display = display[:e.limits.maxCmdBytes]
	}
	return Trace{
		Evaluator:         string(kind),
		UserID:            req.UserID,
		ClientID:          req.ClientID,
		Service:           req.Service,
		Protocol:          req.Protocol,
		Cmd:               req.Cmd,
		CmdArgs:           cmdArgs,
		DisplayCmd:        display,
		RequestArguments:  traceAVs(req.Arguments),
		AuthenMethod:      req.AuthenMethod.String(),
		Privilege:         uint8(req.Privilege),
		EffectiveGroupIDs: ids,
		Steps:             []TraceStep{},
		Arguments:         []TraceAV{},
	}
}

func (e *Engine) normalize(req Request) Request {
	svc, proto, cmd, cmdPresent, args := extractFromAVs(req.Arguments)
	if req.Service == "" {
		req.Service = svc
	}
	if req.Protocol == "" {
		req.Protocol = proto
	}
	if req.Cmd == "" && cmdPresent {
		req.Cmd = cmd
	}
	if len(req.CmdArgs) == 0 && len(args) > 0 {
		req.CmdArgs = args
	}
	if req.CmdArgs == nil {
		req.CmdArgs = []string{}
	}
	return req
}

func commandKey(req Request) string {
	return req.Cmd
}

func (e *Engine) userValid(u compiledUser) bool {
	now := e.now()
	if now.IsZero() {
		return true
	}
	if u.validAfter != nil && now.Before(*u.validAfter) {
		return false
	}
	if u.validBefore != nil && !now.Before(*u.validBefore) {
		return false
	}
	return true
}

func clientAllowed(u compiledUser, clientID string) bool {
	if len(u.clientIDs) == 0 {
		return true
	}
	if clientID == "" {
		return false
	}
	for _, id := range u.clientIDs {
		if id == clientID {
			return true
		}
	}
	return false
}
