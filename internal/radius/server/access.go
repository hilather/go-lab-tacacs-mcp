package server

import (
	"context"
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

const (
	chapPasswordWireLen = 17
	methodPAP           = "pap"
	methodCHAP          = "chap"
)

// AccessAuthenticator is the AAA access facade.
type AccessAuthenticator interface {
	AuthenticateAccess(ctx context.Context, in aaa.RadiusAccessAttempt) (aaa.RadiusAccessDecision, error)
}

// Access handles Access-Request after UDP client resolution. Accounting
// is delegated to Stub. Credential pass evaluates compiled RADIUS policy.
// Store is the Challenge State gate. EAP Identity/MD5 is the first
// production Challenge provider. Entropy is injectable; nil uses crypto/rand.
type Access struct {
	AAA     AccessAuthenticator
	Store   *radiusruntime.ChallengeStore
	Entropy io.Reader
	Metrics *observability.Recorder
}

// Handle implements Handler. Permit is Access-Accept; deny and errors
// are Access-Reject. Message-Authenticator is first on every reply.
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

	if state, present, reason := extractState(in.Packet.Attributes); present {
		if reason != "" {
			return replyAccess(in, codec.CodeAccessReject, reason, nil)
		}
		rec, reason := consumeContinuation(a.Store, in, state)
		if reason != "" {
			return replyAccess(in, codec.CodeAccessReject, reason, nil)
		}
		defer crypto.Wipe(rec.MD5Challenge)
		return a.handleEAPContinuation(ctx, in, rec)
	}
	if in.Packet.Attributes.AllOf(attribute.TypeEAPMessage).Len() > 0 {
		return a.handleEAPStart(ctx, in)
	}

	user, ev, reason, wipe := extractAccessEvidence(in)
	defer wipe()
	if reason != "" {
		return replyAccess(in, codec.CodeAccessReject, reason, nil)
	}
	if a.AAA == nil {
		return replyAccess(in, codec.CodeAccessReject, ReasonInternal, nil)
	}

	dec, err := a.AAA.AuthenticateAccess(ctx, aaa.RadiusAccessAttempt{
		Context: domain.RequestContext{
			Protocol:         domain.ProtocolRADIUS,
			Carrier:          requestCarrier(in),
			ListenerRole:     domain.RoleAccess,
			ListenerID:       in.ListenerID,
			ClientID:         in.ClientID,
			EndpointID:       in.EndpointID,
			SnapshotRevision: in.Revision,
		},
		UserID:     user,
		Evidence:   ev,
		Attributes: policySafeAttrs(in.Packet.Attributes),
	})
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return Result{Action: ActionDiscard, Reason: ReasonOverload}
		}
		return replyAccess(in, codec.CodeAccessReject, ReasonInternal, nil)
	}
	if dec.Outcome == aaa.RadiusAccessAccept {
		return replyAccess(in, codec.CodeAccessAccept, ReasonOK, dec.ReplyAttributes)
	}
	// PAP/CHAP never return Challenge from AAA; do not advertise it.
	if dec.Outcome == aaa.RadiusAccessChallenge {
		return replyAccess(in, codec.CodeAccessReject, ReasonInternal, nil)
	}
	return replyAccess(in, codec.CodeAccessReject, wireAccessReason(dec.ReasonCode), dec.ReplyAttributes)
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
	eaps := in.Packet.Attributes.AllOf(attribute.TypeEAPMessage)
	ms := collectMSCHAP(in.Packet.Attributes)

	if paps.Len() > 1 || chaps.Len() > 1 || chals.Len() > 1 || (paps.Len() > 0 && chaps.Len() > 0) {
		return user, ev, ReasonConflictingAuth, wipe
	}
	if ms.present() && (paps.Len() > 0 || chaps.Len() > 0 || eaps.Len() > 0) {
		return user, ev, ReasonConflictingAuth, wipe
	}
	if eaps.Len() > 0 {
		return user, ev, ReasonUnsupportedMethod, wipe
	}
	if ms.present() {
		got, reason, wipe := extractMSCHAPEvidence(in, ms, wipe)
		return user, got, reason, wipe
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
	case ReasonPolicy:
		return ReasonPolicy
	case ReasonBadCredentials, ReasonUnsupportedMethod, ReasonInternal,
		ReasonMissingUsername, ReasonConflictingAuth, ReasonCHAPPasswordLength,
		ReasonPasswordChangeRequired, ReasonInvalidState, ReasonChallengeExpired,
		ReasonChallengeBinding, ReasonChallengeCapacity, ReasonChallenge,
		ReasonUnsupportedEAPMethod, ReasonEAPTooLong:
		return code
	default:
		return ReasonBadCredentials
	}
}

func policySafeAttrs(in attribute.RawSet) attribute.RawSet {
	if in.Len() == 0 {
		return nil
	}
	out := make(attribute.RawSet, 0, in.Len())
	for _, a := range in {
		if attribute.Sensitive(a.Type) || attribute.MicrosoftSecret(a) || a.Type == attribute.TypeMessageAuthenticator || a.Type == attribute.TypeProxyState || a.Type == attribute.TypeState || a.Type == attribute.TypeEAPMessage {
			continue
		}
		out = append(out, a.Clone())
	}
	return out
}

func replyAttrsLegal(code codec.Code, attrs attribute.RawSet) bool {
	pkt := uint8(code)
	for _, a := range attrs {
		if !attribute.Builtin().AllowedIn(a.Type, pkt) {
			return false
		}
	}
	return true
}

func replyAccess(in Request, code codec.Code, reason string, policy attribute.RawSet) Result {
	if policy.Len() > 0 && !replyAttrsLegal(code, policy) {
		if code == codec.CodeAccessAccept {
			return replyAccess(in, codec.CodeAccessReject, ReasonInternal, nil)
		}
		policy = nil
	}
	wire, err := ReplyAccess(in.Secret, code, in.Packet.Identifier, in.Packet.Authenticator, in.Packet.Attributes, policy)
	if err != nil {
		return Result{Action: ActionDiscard, Reason: ReasonMalformedHeader}
	}
	return Result{Action: ActionReply, Reason: reason, Response: wire}
}
