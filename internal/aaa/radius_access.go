package aaa

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	policyradius "github.com/hilather/go-lab-tacacs-mcp/internal/policy/radius"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// RadiusAccessOutcome is the AAA decision for one Access-Request.
// There is no Access-Error packet; after integrity the wire is Accept or Reject.
type RadiusAccessOutcome string

const (
	RadiusAccessAccept RadiusAccessOutcome = "accept"
	RadiusAccessReject RadiusAccessOutcome = "reject"
	RadiusAccessError  RadiusAccessOutcome = "error"
)

func (o RadiusAccessOutcome) String() string { return string(o) }

// Wire reason_code values AuthenticateAccess returns (design §5.7).
const (
	AccessReasonOK                = "ok"
	AccessReasonBadCredentials    = "reject_bad_credentials"
	AccessReasonPolicy            = "reject_policy"
	AccessReasonUnsupportedMethod = "reject_unsupported_method"
	AccessReasonInternal          = "internal_error"
)

// RadiusAccessAttempt is protocol-neutral access evidence. Hidden
// User-Password must already have been unhidden by the adapter.
// Attributes are request TLVs; secret types are ignored and wiped.
type RadiusAccessAttempt struct {
	Context    domain.RequestContext
	UserID     string
	Evidence   CredentialEvidence
	Attributes attribute.RawSet
}

// RadiusAccessDecision is Accept/Reject plus a metrics-safe reason.
// ReplyAttributes are policy profile attrs only (no Message-Authenticator).
type RadiusAccessDecision struct {
	Outcome         RadiusAccessOutcome
	ReasonCode      string
	UserID          string
	ReplyAttributes attribute.RawSet
	Trace           policyradius.Trace
}

// AuthenticateAccess verifies PAP/CHAP evidence, then evaluates the
// snapshot-held RADIUS policy engine. Permit is Access-Accept with legal
// profile attributes. Deny, default deny, and evaluator errors are
// Access-Reject. There are no user/group RADIUS rules.
func (s *Service) AuthenticateAccess(ctx context.Context, in RadiusAccessAttempt) (RadiusAccessDecision, error) {
	if s == nil {
		return rejectAccess("", AccessReasonInternal), domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return rejectAccess("", AccessReasonInternal), err
	}
	if in.Context.Protocol != "" && in.Context.Protocol != domain.ProtocolRADIUS {
		in.Evidence.Password.Wipe()
		wipeSecretAttrs(in.Attributes)
		return rejectAccess("", AccessReasonInternal), domain.NewError(domain.CodeInvalidArgument, "RADIUS access protocol must be radius").
			WithDetail("protocol", in.Context.Protocol.String())
	}

	user := canonUser(in.UserID)
	if !in.Evidence.Method.Valid() {
		in.Evidence.Password.Wipe()
		wipeSecretAttrs(in.Attributes)
		return rejectAccess(user, AccessReasonUnsupportedMethod), nil
	}

	snap := s.snap()
	if snap == nil {
		in.Evidence.Password.Wipe()
		wipeSecretAttrs(in.Attributes)
		return rejectAccess(user, AccessReasonInternal), domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}

	clientID := in.Context.ClientID
	method := in.Evidence.Method
	outcome := s.verifyAgainst(ctx, snap, user, clientID, in.Evidence)
	in.Evidence.Password.Wipe()
	reqAttrs := policyRequestAttrs(in.Attributes)
	wipeSecretAttrs(in.Attributes)

	switch outcome {
	case domain.AuthPass:
		return evaluateAccess(snap, user, clientID, in.Context.EndpointID, method, reqAttrs), nil
	case domain.AuthReject:
		return rejectAccess(user, AccessReasonBadCredentials), nil
	default:
		return rejectAccess(user, AccessReasonInternal), nil
	}
}

// ExplainRADIUSAccess evaluates the compiled RADIUS engine without verifying
// credentials. It is the same walk AuthenticateAccess uses after a pass.
func ExplainRADIUSAccess(snap *state.Snapshot, userID, clientID, endpointID string, method domain.AuthMethod, attrs attribute.RawSet) RadiusAccessDecision {
	user := canonUser(userID)
	reqAttrs := policyRequestAttrs(attrs)
	wipeSecretAttrs(attrs)
	return evaluateAccess(snap, user, clientID, endpointID, method, reqAttrs)
}

func evaluateAccess(snap *state.Snapshot, user, clientID, endpointID string, method domain.AuthMethod, attrs policyradius.TypedSet) RadiusAccessDecision {
	if snap == nil {
		return rejectAccess(user, AccessReasonInternal)
	}
	eng := snap.RADIUSPolicies()
	res := eng.Evaluate(policyradius.Request{
		UserID:     user,
		ClientID:   clientID,
		EndpointID: endpointID,
		Method:     method,
		Groups:     effectiveRADIUSGroups(snap, user, clientID),
		Attributes: attrs,
	})
	return mapPolicyResult(user, res)
}

func mapPolicyResult(user string, res policyradius.Result) RadiusAccessDecision {
	switch res.Effect {
	case domain.EffectPermit:
		raw, err := encodePolicyReply(res.ReplyAttributes, attribute.PacketAccessAccept)
		if err != nil {
			d := rejectAccess(user, AccessReasonInternal)
			d.Trace = res.Trace
			return d
		}
		return RadiusAccessDecision{
			Outcome:         RadiusAccessAccept,
			ReasonCode:      AccessReasonOK,
			UserID:          user,
			ReplyAttributes: raw,
			Trace:           res.Trace,
		}
	case domain.EffectDeny:
		raw, err := encodePolicyReply(res.ReplyAttributes, attribute.PacketAccessReject)
		if err != nil {
			d := rejectAccess(user, AccessReasonInternal)
			d.Trace = res.Trace
			return d
		}
		d := rejectAccess(user, AccessReasonPolicy)
		d.ReplyAttributes = raw
		d.Trace = res.Trace
		return d
	default:
		d := rejectAccess(user, AccessReasonInternal)
		d.Trace = res.Trace
		return d
	}
}

func effectiveRADIUSGroups(snap *state.Snapshot, userID, clientID string) []string {
	if snap == nil {
		return nil
	}
	u, ok := snap.User(userID)
	if !ok || !u.User.Enabled {
		return nil
	}
	seen := make(map[string]struct{}, len(u.User.GroupIDs)+4)
	out := make([]string, 0, len(u.User.GroupIDs)+4)
	add := func(id string) {
		if id == "" {
			return
		}
		if _, dup := seen[id]; dup {
			return
		}
		g, ok := snap.Group(id)
		if !ok || !g.Group.Enabled {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, id := range u.User.GroupIDs {
		add(id)
	}
	if c, ok := snap.Client(clientID); ok {
		for _, id := range c.Client.Authorization.DefaultGroupIDs {
			add(id)
		}
	}
	return out
}

func rejectAccess(user, reason string) RadiusAccessDecision {
	return RadiusAccessDecision{
		Outcome:    RadiusAccessReject,
		ReasonCode: reason,
		UserID:     user,
	}
}
