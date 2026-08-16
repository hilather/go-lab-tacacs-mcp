package server

import (
	"context"
	"crypto/rand"
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

const (
	eapCodeRequest  = 1
	eapCodeResponse = 2
	eapCodeSuccess  = 3
	eapCodeFailure  = 4

	eapTypeIdentity = 1
	eapTypeNAK      = 3
	eapTypeMD5      = 4

	eapHeaderLen   = 4
	eapMD5ValueLen = 16
	eapStateLen    = 16
	maxEAPPayload  = 1020 // 4 × 253 (RFC 3579 concatenation bound)
	methodEAP      = "eap"
)

type eapPacket struct {
	Code       byte
	Identifier byte
	Type       byte
	Data       []byte
	HasType    bool
}

func concatEAPMessage(attrs attribute.RawSet) ([]byte, string) {
	all := attrs.AllOf(attribute.TypeEAPMessage)
	if all.Len() == 0 {
		return nil, ""
	}
	n := 0
	for _, a := range all {
		n += len(a.Value)
		if n > maxEAPPayload {
			return nil, ReasonEAPTooLong
		}
	}
	out := make([]byte, 0, n)
	for _, a := range all {
		out = append(out, a.Value...)
	}
	return out, ""
}

func parseEAP(b []byte) (eapPacket, string) {
	if len(b) < eapHeaderLen {
		return eapPacket{}, ReasonUnsupportedEAPMethod
	}
	length := int(b[2])<<8 | int(b[3])
	if length != len(b) || length < eapHeaderLen {
		return eapPacket{}, ReasonUnsupportedEAPMethod
	}
	p := eapPacket{Code: b[0], Identifier: b[1]}
	switch p.Code {
	case eapCodeSuccess, eapCodeFailure:
		if length != eapHeaderLen {
			return eapPacket{}, ReasonUnsupportedEAPMethod
		}
		return p, ""
	case eapCodeRequest, eapCodeResponse:
		if length < eapHeaderLen+1 {
			return eapPacket{}, ReasonUnsupportedEAPMethod
		}
		p.HasType = true
		p.Type = b[4]
		if length > eapHeaderLen+1 {
			p.Data = append([]byte(nil), b[5:]...)
		}
		return p, ""
	default:
		return eapPacket{}, ReasonUnsupportedEAPMethod
	}
}

func encodeEAP(p eapPacket) []byte {
	if p.Code == eapCodeSuccess || p.Code == eapCodeFailure {
		return []byte{p.Code, p.Identifier, 0, eapHeaderLen}
	}
	n := eapHeaderLen + 1 + len(p.Data)
	out := make([]byte, n)
	out[0] = p.Code
	out[1] = p.Identifier
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	out[4] = p.Type
	copy(out[5:], p.Data)
	return out
}

func genericEAPFailure(id byte) []byte {
	return []byte{eapCodeFailure, id, 0, eapHeaderLen}
}

func eapSuccess(id byte) []byte {
	return []byte{eapCodeSuccess, id, 0, eapHeaderLen}
}

func eapRequestIdentity(id byte) []byte {
	return encodeEAP(eapPacket{Code: eapCodeRequest, Identifier: id, Type: eapTypeIdentity, HasType: true})
}

func eapRequestMD5(id byte, challenge []byte) []byte {
	data := make([]byte, 1+len(challenge))
	data[0] = byte(len(challenge))
	copy(data[1:], challenge)
	return encodeEAP(eapPacket{Code: eapCodeRequest, Identifier: id, Type: eapTypeMD5, HasType: true, Data: data})
}

func parseMD5Response(data []byte) ([]byte, bool) {
	if len(data) < 1+eapMD5ValueLen || int(data[0]) != eapMD5ValueLen || len(data) < 1+int(data[0]) {
		return nil, false
	}
	out := make([]byte, eapMD5ValueLen)
	copy(out, data[1:1+eapMD5ValueLen])
	return out, true
}

func eapMessageAttrs(pkt []byte) attribute.RawSet {
	if len(pkt) == 0 {
		return nil
	}
	out := make(attribute.RawSet, 0, 1)
	for len(pkt) > 0 {
		n := len(pkt)
		if n > attribute.MaxValueLength {
			n = attribute.MaxValueLength
		}
		out = append(out, attribute.Raw{Type: attribute.TypeEAPMessage, Value: append([]byte(nil), pkt[:n]...)})
		pkt = pkt[n:]
	}
	return out
}

func eapTypeLabel(typ byte, hasType bool) string {
	if !hasType {
		return observability.EAPTypeOther
	}
	switch typ {
	case eapTypeIdentity:
		return observability.EAPTypeIdentity
	case eapTypeMD5:
		return observability.EAPTypeMD5
	case eapTypeNAK:
		return observability.EAPTypeNAK
	default:
		return observability.EAPTypeOther
	}
}

func (a Access) entropy() io.Reader {
	if a.Entropy != nil {
		return a.Entropy
	}
	return rand.Reader
}

func (a Access) noteEAP(typ byte, hasType bool, outcome string) {
	if a.Metrics == nil {
		return
	}
	a.Metrics.RADIUSEAP(eapTypeLabel(typ, hasType), outcome)
}

func (a Access) noteChallenge(result string) {
	if a.Metrics == nil {
		return
	}
	a.Metrics.RADIUSChallenge(result)
}

func (a Access) handleEAPStart(_ context.Context, in Request) Result {
	if papOrCHAPPresent(in) {
		return a.eapReject(in, ReasonConflictingAuth, 0, 0, false)
	}
	if !methodAllowed(in.AllowedMethods, methodEAP) {
		return replyAccess(in, codec.CodeAccessReject, ReasonUnsupportedMethod, nil)
	}
	raw, reason := concatEAPMessage(in.Packet.Attributes)
	if reason != "" {
		return a.eapReject(in, reason, 0, 0, false)
	}
	pkt, reason := parseEAP(raw)
	crypto.Wipe(raw)
	if reason != "" {
		return a.eapReject(in, reason, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	if pkt.Code != eapCodeResponse {
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	switch pkt.Type {
	case eapTypeIdentity:
		return a.startFromIdentity(in, pkt)
	case eapTypeNAK:
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	case eapTypeMD5:
		return a.eapReject(in, ReasonInvalidState, pkt.Identifier, pkt.Type, pkt.HasType)
	default:
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	}
}

func (a Access) handleEAPContinuation(ctx context.Context, in Request, rec runtime.ChallengeRecord) Result {
	if papOrCHAPPresent(in) {
		return a.eapReject(in, ReasonConflictingAuth, rec.EAPID, rec.EAPType, true)
	}
	raw, reason := concatEAPMessage(in.Packet.Attributes)
	if reason != "" {
		return a.eapReject(in, reason, rec.EAPID, rec.EAPType, true)
	}
	if len(raw) == 0 {
		return replyAccess(in, codec.CodeAccessReject, ReasonUnsupportedMethod, nil)
	}
	pkt, reason := parseEAP(raw)
	crypto.Wipe(raw)
	if reason != "" {
		return a.eapReject(in, reason, rec.EAPID, rec.EAPType, true)
	}
	if pkt.Code != eapCodeResponse {
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	switch rec.Step {
	case runtime.StepIdentity:
		if pkt.Type == eapTypeIdentity {
			return a.startFromIdentity(in, pkt)
		}
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	case runtime.StepMD5Challenge:
		if pkt.Type == eapTypeNAK {
			return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
		}
		if pkt.Type != eapTypeMD5 {
			return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
		}
		if pkt.Identifier != rec.EAPID {
			return a.eapReject(in, ReasonInvalidState, pkt.Identifier, pkt.Type, pkt.HasType)
		}
		return a.verifyMD5(ctx, in, rec, pkt)
	default:
		return a.eapReject(in, ReasonInvalidState, pkt.Identifier, pkt.Type, pkt.HasType)
	}
}

func (a Access) startFromIdentity(in Request, pkt eapPacket) Result {
	ident := string(pkt.Data)
	userName, present, reason := singleUserName(in.Packet.Attributes)
	if reason != "" {
		return a.eapReject(in, reason, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	if ident != "" && present && !sameRADIUSUser(ident, userName) {
		return a.eapReject(in, ReasonConflictingAuth, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	user := ident
	if user == "" {
		user = userName
	}
	if user == "" {
		return a.issueIdentityChallenge(in, pkt.Identifier)
	}
	return a.issueMD5Challenge(in, user, pkt.Identifier)
}

func (a Access) issueIdentityChallenge(in Request, peerID byte) Result {
	state, err := readRand(a.entropy(), eapStateLen)
	if err != nil {
		return a.eapReject(in, ReasonInternal, peerID, eapTypeIdentity, true)
	}
	id := peerID + 1
	reason := IssueChallenge(a.Store, in, runtime.ChallengeIssue{
		State:      state,
		UserID:     "",
		Method:     methodEAP,
		EAPID:      id,
		EAPType:    eapTypeIdentity,
		Step:       runtime.StepIdentity,
		EndpointID: in.EndpointID,
		ClientID:   in.ClientID,
	})
	if reason != "" {
		crypto.Wipe(state)
		return a.eapReject(in, reason, peerID, eapTypeIdentity, true)
	}
	a.noteChallenge(observability.ChallengeResultIssue)
	a.noteEAP(eapTypeIdentity, true, observability.OutcomeAccessChallenge)
	extra := attribute.RawSet{
		{Type: attribute.TypeState, Value: state},
	}
	extra = append(extra, eapMessageAttrs(eapRequestIdentity(id))...)
	return replyAccess(in, codec.CodeAccessChallenge, ReasonChallenge, extra)
}

func (a Access) issueMD5Challenge(in Request, user string, peerID byte) Result {
	state, err := readRand(a.entropy(), eapStateLen)
	if err != nil {
		return a.eapReject(in, ReasonInternal, peerID, eapTypeIdentity, true)
	}
	chal, err := readRand(a.entropy(), eapMD5ValueLen)
	if err != nil {
		crypto.Wipe(state)
		return a.eapReject(in, ReasonInternal, peerID, eapTypeIdentity, true)
	}
	id := peerID + 1
	reason := IssueChallenge(a.Store, in, runtime.ChallengeIssue{
		State:        state,
		UserID:       user,
		Method:       methodEAP,
		EAPID:        id,
		EAPType:      eapTypeMD5,
		Step:         runtime.StepMD5Challenge,
		MD5Challenge: chal,
		EndpointID:   in.EndpointID,
		ClientID:     in.ClientID,
	})
	if reason != "" {
		crypto.Wipe(state)
		crypto.Wipe(chal)
		return a.eapReject(in, reason, peerID, eapTypeIdentity, true)
	}
	req := eapRequestMD5(id, chal)
	crypto.Wipe(chal)
	a.noteChallenge(observability.ChallengeResultIssue)
	a.noteEAP(eapTypeMD5, true, observability.OutcomeAccessChallenge)
	extra := attribute.RawSet{
		{Type: attribute.TypeState, Value: state},
	}
	extra = append(extra, eapMessageAttrs(req)...)
	return replyAccess(in, codec.CodeAccessChallenge, ReasonChallenge, extra)
}

func (a Access) verifyMD5(ctx context.Context, in Request, rec runtime.ChallengeRecord, pkt eapPacket) Result {
	hash, ok := parseMD5Response(pkt.Data)
	if !ok {
		return a.eapReject(in, ReasonBadCredentials, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	if a.AAA == nil {
		crypto.Wipe(hash)
		return a.eapReject(in, ReasonInternal, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	user := rec.UserID
	if user == "" {
		if name, present, reason := singleUserName(in.Packet.Attributes); reason != "" {
			crypto.Wipe(hash)
			return a.eapReject(in, reason, pkt.Identifier, pkt.Type, pkt.HasType)
		} else if present {
			user = name
		}
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
		UserID: user,
		Evidence: aaa.CredentialEvidence{
			Method:    domain.AuthMethodEAP,
			CHAPID:    pkt.Identifier,
			Challenge: append([]byte(nil), rec.MD5Challenge...),
			Response:  hash,
		},
		Attributes: policySafeAttrs(in.Packet.Attributes),
	})
	crypto.Wipe(hash)
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return Result{Action: ActionDiscard, Reason: ReasonOverload}
		}
		return a.eapReject(in, ReasonInternal, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	if dec.Outcome == aaa.RadiusAccessAccept {
		a.noteChallenge(observability.ChallengeResultContinue)
		a.noteEAP(eapTypeMD5, true, observability.OutcomeAccessAccept)
		extra := eapMessageAttrs(eapSuccess(pkt.Identifier))
		if dec.ReplyAttributes.Len() > 0 {
			extra = append(extra, dec.ReplyAttributes...)
		}
		return replyAccess(in, codec.CodeAccessAccept, ReasonOK, extra)
	}
	reason := wireAccessReason(dec.ReasonCode)
	// must_change, bad password, policy deny, and other EAP rejects share
	// generic EAP-Failure on the wire (ADR 0022).
	return a.eapReject(in, reason, pkt.Identifier, pkt.Type, pkt.HasType)
}

func (a Access) eapReject(in Request, reason string, id, typ byte, hasType bool) Result {
	outcome := observability.OutcomeAccessReject
	if reason == ReasonChallenge {
		outcome = observability.OutcomeAccessChallenge
	}
	a.noteEAP(typ, hasType, outcome)
	switch reason {
	case ReasonInvalidState:
		a.noteChallenge(observability.ChallengeResultReplayReject)
	case ReasonChallengeExpired:
		a.noteChallenge(observability.ChallengeResultExpired)
	case ReasonChallengeBinding:
		a.noteChallenge(observability.ChallengeResultBinding)
	case ReasonChallengeCapacity:
		a.noteChallenge(observability.ChallengeResultCapacity)
	}
	return replyAccess(in, codec.CodeAccessReject, reason, eapMessageAttrs(genericEAPFailure(id)))
}

func papOrCHAPPresent(in Request) bool {
	return in.Packet.Attributes.AllOf(attribute.TypeUserPassword).Len() > 0 ||
		in.Packet.Attributes.AllOf(attribute.TypeCHAPPassword).Len() > 0
}

func singleUserName(attrs attribute.RawSet) (string, bool, string) {
	names := attrs.AllOf(attribute.TypeUserName)
	if names.Len() == 0 {
		return "", false, ""
	}
	if names.Len() != 1 || len(names[0].Value) == 0 {
		return "", false, ReasonMissingUsername
	}
	return string(names[0].Value), true, ""
}

func sameRADIUSUser(a, b string) bool {
	ca, ea := credentials.CanonicalUsername(a)
	cb, eb := credentials.CanonicalUsername(b)
	if ea != nil || eb != nil {
		return false
	}
	return ca == cb
}

func readRand(r io.Reader, n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
