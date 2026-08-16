package radius

import (
	"bytes"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Evaluate walks user, then effectiveGroups, then client, then fallback.
// First matching rule wins. No match is deny. A nil engine is an error
// (fail closed, never permit).
func (e *Engine) Evaluate(req Request) Result {
	if e == nil {
		return errorResult(newTrace(req), "policy engine is not compiled")
	}
	tr := newTrace(req)
	if u, ok := e.users[req.UserID]; ok && u.enabled && u.policyID != "" {
		if res, done := e.walk(sourceUserPrefix+u.policyID, u.policyID, req, &tr); done {
			return res
		}
	}
	for _, g := range e.effectiveGroups(req.UserID, req.ClientID) {
		if g.policyID == "" {
			continue
		}
		if res, done := e.walk(sourceGroupPrefix+g.policyID, g.policyID, req, &tr); done {
			return res
		}
	}
	if binding, ok := e.clients[req.ClientID]; ok {
		if req.EndpointID == "" || req.EndpointID == binding.endpointID {
			if binding.policyID != "" {
				if res, done := e.walk(sourceClientPrefix+binding.policyID, binding.policyID, req, &tr); done {
					return res
				}
			}
		}
	}
	if e.fallback != "" {
		if res, done := e.walk(sourceFallback, e.fallback, req, &tr); done {
			return res
		}
	}
	return denyResult(tr, "no matching access rule")
}

func (e *Engine) walk(source, policyID string, req Request, tr *Trace) (Result, bool) {
	p, ok := e.policies[policyID]
	if !ok {
		return errorResult(*tr, "compiled policy missing"), true
	}
	for _, r := range p.rules {
		matched, reason := matchRule(r, req)
		tr.Steps = append(tr.Steps, TraceStep{
			Source:  source,
			RuleID:  r.id,
			Matched: matched,
			Reason:  reason,
		})
		if matched {
			return matchedResult(*tr, source, r.id, r.effect, r.reply), true
		}
	}
	return Result{}, false
}

func matchRule(r compiledRule, req Request) (bool, string) {
	if len(r.match.groupsAny) > 0 {
		if !groupsIntersect(req.Groups, r.match.groupsAny) {
			return false, "groups_any mismatch"
		}
	}
	if r.match.method != nil {
		if req.Method != *r.match.method {
			return false, "method mismatch"
		}
	}
	for _, a := range r.match.attrs {
		ok, reason := matchAttr(a, req.Attributes)
		if !ok {
			return false, reason
		}
	}
	return true, "matched"
}

func matchAttr(a compiledAttrMatch, set TypedSet) (bool, string) {
	switch a.op {
	case config.RADIUSMatchOpPresent:
		if !set.Present(a.key) {
			return false, "attribute " + a.label + " not present"
		}
	case config.RADIUSMatchOpAbsent:
		if set.Present(a.key) {
			return false, "attribute " + a.label + " present"
		}
	case config.RADIUSMatchOpEquals:
		got, ok := set.First(a.key)
		if !ok {
			return false, "attribute " + a.label + " equals mismatch"
		}
		if !typedEqual(got, a.equals) {
			return false, "attribute " + a.label + " equals mismatch"
		}
	default:
		return false, "attribute " + a.label + " unsupported op"
	}
	return true, "matched"
}

func typedEqual(got, want Typed) bool {
	if !got.Key.Equal(want.Key) {
		return false
	}
	if want.Kind == KindInteger || want.Kind == KindTime {
		return got.Uint == want.Uint
	}
	if want.Kind == KindIPv4 || want.Kind == KindIPv6 {
		return got.Addr.IsValid() && got.Addr == want.Addr
	}
	if len(want.Raw) > 0 || want.Kind == KindString || want.Kind == KindVSA {
		return bytes.Equal(got.Raw, want.Raw)
	}
	return got.Text == want.Text
}

func groupsIntersect(have, want []string) bool {
	if len(have) == 0 || len(want) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(have))
	for _, g := range have {
		if g != "" {
			set[g] = struct{}{}
		}
	}
	for _, g := range want {
		if _, ok := set[g]; ok {
			return true
		}
	}
	return false
}

func newTrace(req Request) Trace {
	method := ""
	if req.Method.Valid() {
		method = req.Method.String()
	}
	return Trace{
		Evaluator:  evaluatorName,
		UserID:     req.UserID,
		ClientID:   req.ClientID,
		EndpointID: req.EndpointID,
		Method:     method,
		Groups:     cloneStrings(req.Groups),
		Steps:      []TraceStep{},
	}
}

func denyResult(tr Trace, reason string) Result {
	tr.DefaultDeny = reason
	tr.Winner = nil
	tr.Effect = domain.EffectDeny.String()
	return Result{Effect: domain.EffectDeny, ReplyAttributes: TypedSet{}, Trace: tr}
}

func errorResult(tr Trace, reason string) Result {
	tr.Error = reason
	tr.Winner = nil
	tr.Effect = domain.EffectError.String()
	tr.DefaultDeny = ""
	return Result{Effect: domain.EffectError, ReplyAttributes: TypedSet{}, Trace: tr}
}

func matchedResult(tr Trace, source, ruleID string, effect domain.Effect, reply TypedSet) Result {
	if err := CheckReplyLegal(effect, reply); err != nil {
		return errorResult(tr, "illegal reply attributes")
	}
	tr.Winner = &TraceWinner{Source: source, RuleID: ruleID, Effect: effect.String()}
	tr.Effect = effect.String()
	tr.DefaultDeny = ""
	return Result{Effect: effect, ReplyAttributes: reply.clone(), Trace: tr}
}

// CheckReplyLegal reports whether attrs may appear on the Access-Accept
// (permit) or Access-Reject (deny) packet. Compile already enforces this;
// evaluation re-checks so a corrupted engine cannot emit an illegal reply.
func CheckReplyLegal(effect domain.Effect, attrs TypedSet) error {
	packet := packetAccessAccept
	if effect == domain.EffectDeny {
		packet = packetAccessReject
	} else if effect != domain.EffectPermit {
		return nil
	}
	for _, a := range attrs {
		if err := replyAttrLegal(packet, a); err != nil {
			return err
		}
	}
	return nil
}

func replyAttrLegal(packet int, a Typed) error {
	if a.Key.Vendor != 0 {
		if packet == packetAccessReject {
			return domain.NewError(domain.CodeInvalidArgument, "deny rules may include only Access-Reject attributes (Reply-Message)")
		}
		return nil
	}
	def, ok := builtinDict.lookupCode(a.Key.Code)
	if !ok {
		return domain.NewError(domain.CodeInvalidArgument, "unknown RADIUS attribute code")
	}
	if def.Secret || def.ServerOwned {
		return domain.NewError(domain.CodeInvalidArgument, "attribute is not a policy reply attribute")
	}
	if packet == packetAccessAccept && !def.allowAccept {
		return domain.NewError(domain.CodeInvalidArgument, "attribute is not legal in Access-Accept")
	}
	if packet == packetAccessReject && !def.allowReject {
		return domain.NewError(domain.CodeInvalidArgument, "deny rules may include only Access-Reject attributes (Reply-Message)")
	}
	return nil
}
