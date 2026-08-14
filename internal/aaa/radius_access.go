package aaa

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// RadiusAccessOutcome is the AAA decision for one Access-Request.
// There is no Access-Error packet; after integrity the wire is Accept or Reject.
type RadiusAccessOutcome string

const (
	// RadiusAccessAccept is reserved for compiled policy permit (not this PR).
	RadiusAccessAccept RadiusAccessOutcome = "accept"
	RadiusAccessReject RadiusAccessOutcome = "reject"
	RadiusAccessError  RadiusAccessOutcome = "error"
)

func (o RadiusAccessOutcome) String() string { return string(o) }

// Wire reason_code values AuthenticateAccess returns (design §5.7).
const (
	AccessReasonBadCredentials    = "reject_bad_credentials"
	AccessReasonPolicy            = "reject_policy"
	AccessReasonUnsupportedMethod = "reject_unsupported_method"
	AccessReasonInternal          = "internal_error"
)

// RadiusAccessAttempt is protocol-neutral access evidence. Hidden
// User-Password must already have been unhidden by the adapter.
type RadiusAccessAttempt struct {
	Context  domain.RequestContext
	UserID   string
	Evidence CredentialEvidence
}

// RadiusAccessDecision is Accept/Reject plus a metrics-safe reason.
// Reply attributes and policy traces are added when policy evaluation ships.
type RadiusAccessDecision struct {
	Outcome    RadiusAccessOutcome
	ReasonCode string
	UserID     string
}

// AuthenticateAccess verifies PAP/CHAP evidence and applies default-deny.
// It never returns RadiusAccessAccept: permit is a later policy PR.
func (s *Service) AuthenticateAccess(ctx context.Context, in RadiusAccessAttempt) (RadiusAccessDecision, error) {
	if s == nil {
		return rejectAccess("", AccessReasonInternal), domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return rejectAccess("", AccessReasonInternal), err
	}
	if in.Context.Protocol != "" && in.Context.Protocol != domain.ProtocolRADIUS {
		return rejectAccess("", AccessReasonInternal), domain.NewError(domain.CodeInvalidArgument, "RADIUS access protocol must be radius").
			WithDetail("protocol", in.Context.Protocol.String())
	}

	user := canonUser(in.UserID)
	if !in.Evidence.Method.Valid() {
		in.Evidence.Password.Wipe()
		return rejectAccess(user, AccessReasonUnsupportedMethod), nil
	}

	snap := s.snap()
	if snap == nil {
		in.Evidence.Password.Wipe()
		return rejectAccess(user, AccessReasonInternal), domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}

	clientID := in.Context.ClientID
	outcome := s.verifyAgainst(ctx, snap, user, clientID, in.Evidence)
	in.Evidence.Password.Wipe()

	switch outcome {
	case domain.AuthPass:
		// Default deny until RADIUS policy evaluation exists. Never accept.
		return rejectAccess(user, AccessReasonPolicy), nil
	case domain.AuthReject:
		return rejectAccess(user, AccessReasonBadCredentials), nil
	default:
		return rejectAccess(user, AccessReasonInternal), nil
	}
}

func rejectAccess(user, reason string) RadiusAccessDecision {
	return RadiusAccessDecision{
		Outcome:    RadiusAccessReject,
		ReasonCode: reason,
		UserID:     user,
	}
}
