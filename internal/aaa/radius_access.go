package aaa

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	policyradius "github.com/hilather/go-lab-tacacs-mcp/internal/policy/radius"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// RadiusAccessOutcome is the AAA decision for one Access-Request.
// There is no Access-Error packet; after integrity the wire is Accept, Reject,
// or Challenge. RadiusAccessChallenge is unused by PAP/CHAP.
type RadiusAccessOutcome string

const (
	RadiusAccessAccept    RadiusAccessOutcome = "accept"
	RadiusAccessReject    RadiusAccessOutcome = "reject"
	RadiusAccessChallenge RadiusAccessOutcome = "challenge"
	RadiusAccessError     RadiusAccessOutcome = "error"
)

func (o RadiusAccessOutcome) String() string { return string(o) }

// Wire reason_code values AuthenticateAccess returns (design §5.7).
const (
	AccessReasonOK                     = "ok"
	AccessReasonBadCredentials         = "reject_bad_credentials"
	AccessReasonPolicy                 = "reject_policy"
	AccessReasonUnsupportedMethod      = "reject_unsupported_method"
	AccessReasonInternal               = "internal_error"
	AccessReasonPasswordChangeRequired = "reject_password_change_required"
	AccessReasonInvalidState           = "reject_invalid_state"
	AccessReasonChallengeExpired       = "reject_challenge_expired"
	AccessReasonChallengeBinding       = "reject_challenge_binding"
	AccessReasonChallengeCapacity      = "reject_challenge_capacity"
	AccessReasonChallenge              = "challenge"
	AccessReasonUnsupportedEAPMethod   = "reject_unsupported_eap_method"
	AccessReasonEAPTooLong             = "reject_eap_too_long"
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

// RadiusChallenge is the unused-by-PAP/CHAP Challenge payload.
// The adapter stores State; AuthenticateAccess never returns this for PAP/CHAP.
type RadiusChallenge struct {
	Method  domain.AuthMethod
	State   []byte
	Prompt  attribute.RawSet
	Expires time.Time
}

// String omits State and prompt bytes.
func (c RadiusChallenge) String() string {
	return fmt.Sprintf("RadiusChallenge{method=%s state_len=%d}", c.Method, len(c.State))
}

// GoString is the %#v form and never includes State.
func (c RadiusChallenge) GoString() string { return c.String() }

// Format never writes State or prompt values.
func (c RadiusChallenge) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, c.String())
}

// RadiusAccessDecision is Accept/Reject plus a metrics-safe reason.
// ReplyAttributes are policy profile attrs only (no Message-Authenticator).
// Challenge is nil unless Outcome == challenge (not used for PAP/CHAP).
type RadiusAccessDecision struct {
	Outcome         RadiusAccessOutcome
	ReasonCode      string
	UserID          string
	ReplyAttributes attribute.RawSet
	Challenge       *RadiusChallenge
	Trace           policyradius.Trace
}

// AuthenticateAccess verifies PAP/CHAP evidence, then evaluates the
// snapshot-held RADIUS policy engine (user, groups, client, fallback).
// Permit is Access-Accept with legal profile attributes. Deny, default
// deny, and evaluator errors are Access-Reject.
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
		if userMustChangeLogin(snap, user) {
			wipeMSCHAPEvidence(&in.Evidence)
			return rejectAccess(user, AccessReasonPasswordChangeRequired), nil
		}
		dec := evaluateAccess(snap, user, clientID, in.Context.EndpointID, method, reqAttrs)
		if dec.Outcome == RadiusAccessAccept && method == domain.AuthMethodMSCHAPv2 {
			if err := appendMSCHAP2Success(s, ctx, snap, clientID, user, &in.Evidence, &dec); err != nil {
				wipeMSCHAPEvidence(&in.Evidence)
				return rejectAccess(user, AccessReasonInternal), nil
			}
		}
		wipeMSCHAPEvidence(&in.Evidence)
		return dec, nil
	case domain.AuthReject:
		wipeMSCHAPEvidence(&in.Evidence)
		return rejectAccess(user, AccessReasonBadCredentials), nil
	default:
		wipeMSCHAPEvidence(&in.Evidence)
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
	// Groups are omitted when the user is compiled: Evaluate uses the
	// same effectiveGroups membership as the walk. Callers without a
	// compiled user (unit engines) still pass Groups for groups_any.
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

// effectiveRADIUSGroups matches policy/radius effectiveGroups: enabled
// users contribute group_ids, then client default_group_ids, then sort
// by group priority then id. Disabled users omit their own group_ids
// (credentials already rejected them on the wire) but still receive
// client defaults so diagnostics do not drift from Evaluate.
func effectiveRADIUSGroups(snap *state.Snapshot, userID, clientID string) []string {
	if snap == nil {
		return nil
	}
	type ranked struct {
		id       string
		priority int
	}
	seen := make(map[string]struct{}, 8)
	var rankedGroups []ranked
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
		rankedGroups = append(rankedGroups, ranked{id: id, priority: g.Group.Priority})
	}
	if u, ok := snap.User(userID); ok && u.User.Enabled {
		for _, id := range u.User.GroupIDs {
			add(id)
		}
	}
	if c, ok := snap.Client(clientID); ok {
		for _, id := range c.Client.Authorization.DefaultGroupIDs {
			add(id)
		}
	}
	sort.SliceStable(rankedGroups, func(i, j int) bool {
		if rankedGroups[i].priority != rankedGroups[j].priority {
			return rankedGroups[i].priority < rankedGroups[j].priority
		}
		return rankedGroups[i].id < rankedGroups[j].id
	})
	out := make([]string, len(rankedGroups))
	for i, g := range rankedGroups {
		out[i] = g.id
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
