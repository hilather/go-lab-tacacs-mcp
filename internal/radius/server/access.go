package server

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

const (
	chapPasswordWireLen = 17
	methodPAP           = "pap"
	methodCHAP          = "chap"
)

// AccessAuthenticator is the AAA access facade. Implementations must not
// return accept until policy evaluation exists.
type AccessAuthenticator interface {
	AuthenticateAccess(ctx context.Context, in aaa.RadiusAccessAttempt) (aaa.RadiusAccessDecision, error)
}

// Access handles Access-Request after UDP client resolution. Accounting
// is delegated to Stub. Valid credentials still Access-Reject (default-deny).
type Access struct {
	AAA AccessAuthenticator
}

// Handle implements Handler. It never emits Access-Accept.
func (a Access) Handle(ctx context.Context, in Request) Result {
	if ctx != nil && ctx.Err() != nil {
		return Result{Action: ActionDiscard, Reason: ReasonOverload}
	}
	if in.Role == domain.RoleAccounting {
		return Stub{}.Handle(ctx, in)
	}
	if in.Role != domain.RoleAccess || in.Packet.Code != codec.CodeAccessRequest {
		return Result{Action: ActionDiscard, Reason: ReasonInvalidCode}
	}
	if reason := CheckIntegrity(in); reason != "" {
		return Result{Action: ActionDiscard, Reason: reason}
	}

	user, ev, reason, wipe := extractAccessEvidence(in)
	defer wipe()
	if reason != "" {
		return rejectAccess(in, reason)
	}
	if a.AAA == nil {
		return rejectAccess(in, ReasonInternal)
	}

	dec, err := a.AAA.AuthenticateAccess(ctx, aaa.RadiusAccessAttempt{
		Context: domain.RequestContext{
			Protocol:         domain.ProtocolRADIUS,
			Carrier:          domain.CarrierRADIUSUDP,
			ListenerRole:     domain.RoleAccess,
			ListenerID:       in.ListenerID,
			ClientID:         in.ClientID,
			EndpointID:       in.EndpointID,
			SnapshotRevision: in.Revision,
		},
		UserID:   user,
		Evidence: ev,
	})
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return Result{Action: ActionDiscard, Reason: ReasonOverload}
		}
		return rejectAccess(in, ReasonInternal)
	}
	// Fail closed: even a future accept decision stays Access-Reject here.
	return rejectAccess(in, wireAccessReason(dec.ReasonCode))
}

func extractAccessEvidence(in Request) (user string, ev aaa.CredentialEvidence, reason string, wipe func()) {
	wipe = func() {}
	names := in.Packet.Attributes.AllOf(attribute.TypeUserName)
	if names.Len() != 1 || len(names[0].Value) == 0 {
		return "", ev, ReasonMissingUsername, wipe
	}
	user = string(names[0].Value)

	paps := in.Packet.Attributes.AllOf(attribute.TypeUserPassword)
	chaps := in.Packet.Attributes.AllOf(attribute.TypeCHAPPassword)
	chals := in.Packet.Attributes.AllOf(attribute.TypeCHAPChallenge)

	if paps.Len() > 1 || chaps.Len() > 1 || chals.Len() > 1 || (paps.Len() > 0 && chaps.Len() > 0) {
		return user, ev, ReasonConflictingAuth, wipe
	}
	if in.Packet.Attributes.AllOf(attribute.TypeEAPMessage).Len() > 0 {
		return user, ev, ReasonUnsupportedMethod, wipe
	}
	if paps.Len() == 0 && chaps.Len() == 0 {
		return user, ev, ReasonUnsupportedMethod, wipe
	}

	if chaps.Len() == 1 {
		val := chaps[0].Value
		if len(val) != chapPasswordWireLen {
			return user, ev, ReasonCHAPPasswordLength, wipe
		}
		if !methodAllowed(in.AllowedMethods, methodCHAP) {
			return user, ev, ReasonUnsupportedMethod, wipe
		}
		chal := in.Packet.Authenticator[:]
		if chals.Len() == 1 {
			chal = chals[0].Value
		}
		return user, aaa.CredentialEvidence{
			Method:    domain.AuthMethodCHAP,
			CHAPID:    val[0],
			Challenge: append([]byte(nil), chal...),
			Response:  append([]byte(nil), val[1:]...),
		}, "", wipe
	}

	if !methodAllowed(in.AllowedMethods, methodPAP) {
		return user, ev, ReasonUnsupportedMethod, wipe
	}
	plain, err := crypto.UnhideUserPassword(in.Secret, in.Packet.Authenticator, paps[0].Value)
	if err != nil {
		return user, ev, ReasonBadCredentials, wipe
	}
	pw := credentials.NewPassword(plain)
	crypto.Wipe(plain)
	wipe = func() { pw.Wipe() }
	return user, aaa.CredentialEvidence{
		Method:   domain.AuthMethodPassword,
		Password: pw,
	}, "", wipe
}

func methodAllowed(allowed []string, method string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, m := range allowed {
		if m == method {
			return true
		}
	}
	return false
}

func wireAccessReason(code string) string {
	switch code {
	case ReasonOK, ReasonPolicy:
		return ReasonPolicy
	case ReasonBadCredentials, ReasonUnsupportedMethod, ReasonInternal,
		ReasonMissingUsername, ReasonConflictingAuth, ReasonCHAPPasswordLength:
		return code
	default:
		return ReasonBadCredentials
	}
}

func rejectAccess(in Request, reason string) Result {
	wire, err := RejectAccess(in.Secret, in.Packet.Identifier, in.Packet.Authenticator, in.Packet.Attributes)
	if err != nil {
		return Result{Action: ActionDiscard, Reason: ReasonMalformedHeader}
	}
	return Result{Action: ActionReply, Reason: reason, Response: wire}
}
