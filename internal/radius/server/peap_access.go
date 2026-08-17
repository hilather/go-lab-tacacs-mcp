package server

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/eap/peap"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

func (a Access) handlePEAP(ctx context.Context, in Request, rec runtime.ChallengeRecord, pkt eapPacket) Result {
	if pkt.Type != eapTypePEAP {
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	if !methodAllowed(in.AllowedMethods, methodPEAP) {
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	if a.PEAP == nil || a.Tunnels == nil {
		return a.eapReject(in, ReasonInternal, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	tun := a.Tunnels.Get(rec.TunnelID)
	if tun == nil {
		return a.eapReject(in, ReasonInvalidState, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	body, err := peap.Parse(pkt.Data)
	if err != nil {
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	if next, ok := tun.NextFragment(); ok && len(body.TLSData) == 0 {
		return a.issuePEAPContinue(in, rec, next, rec.Step)
	}
	complete, done := tun.BufferFragment(body)
	if !done {
		return a.issuePEAPContinue(in, rec, peap.Encode(peap.Payload{Version: peap.Version0}), rec.Step)
	}
	if !tun.HandshakeComplete() {
		if err := tun.PushClient(complete); err != nil {
			return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
		}
		tun.WaitProgress(2 * time.Second)
		recs := tun.PullServer()
		if tun.HandshakeComplete() {
			if err := tun.WriteApp(peap.IdentityRequest(pkt.Identifier + 1)); err != nil {
				return a.eapReject(in, ReasonInternal, pkt.Identifier, pkt.Type, pkt.HasType)
			}
			recs = append(recs, tun.PullServer()...)
			return a.issuePEAPContinue(in, rec, firstFlight(tun, recs), runtime.StepPEAPInner)
		}
		if err := tun.HandshakeErr(); err != nil && len(recs) == 0 {
			return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
		}
		return a.issuePEAPContinue(in, rec, firstFlight(tun, recs), runtime.StepPEAPHandshake)
	}
	if rec.Step == runtime.StepPEAPFinish {
		a.Tunnels.Delete(rec.TunnelID)
		tun.Close()
		a.noteChallenge(observability.ChallengeResultContinue)
		a.noteEAP(eapTypePEAP, true, observability.OutcomeAccessAccept)
		return replyAccess(in, codec.CodeAccessAccept, ReasonOK, eapMessageAttrs(eapSuccess(pkt.Identifier)))
	}
	if err := tun.PushClient(complete); err != nil {
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	inner, err := tun.ReadApp(2 * time.Second)
	if err != nil {
		return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, pkt.Type, pkt.HasType)
	}
	return a.handlePEAPInner(ctx, in, rec, tun, inner)
}

func firstFlight(tun *peap.Tunnel, tlsRec []byte) []byte {
	if tun == nil {
		return peap.Encode(peap.Payload{Version: peap.Version0})
	}
	return tun.QueueFlight(tlsRec)
}

func (a Access) handlePEAPInner(ctx context.Context, in Request, rec runtime.ChallengeRecord, tun *peap.Tunnel, inner []byte) Result {
	pkt, err := peap.DecodeInner(inner)
	if err != nil {
		return a.eapReject(in, ReasonUnsupportedEAPMethod, rec.EAPID, eapTypePEAP, true)
	}
	switch rec.Step {
	case runtime.StepPEAPInner, runtime.StepPEAPHandshake:
		if pkt.Code != 2 || pkt.Type != peap.InnerIdentity {
			return a.eapReject(in, ReasonUnsupportedEAPMethod, pkt.Identifier, eapTypePEAP, true)
		}
		user := rec.UserID
		if ident := string(pkt.Data); ident != "" {
			user = ident
		}
		chal, err := readRand(a.entropy(), 16)
		if err != nil {
			return a.eapReject(in, ReasonInternal, pkt.Identifier, eapTypePEAP, true)
		}
		msID := pkt.Identifier + 1
		if err := tun.WriteApp(peap.EncodeMSCHAPChallenge(msID, msID, chal, "taclab")); err != nil {
			crypto.Wipe(chal)
			return a.eapReject(in, ReasonInternal, pkt.Identifier, eapTypePEAP, true)
		}
		rec.UserID = user
		rec.MD5Challenge = chal
		rec.EAPID = msID
		return a.issuePEAPContinue(in, rec, firstFlight(tun, tun.PullServer()), runtime.StepPEAPMSCHAP)
	case runtime.StepPEAPMSCHAP:
		msID, resp, name, ok := peap.ParseMSCHAPResponse(pkt)
		if !ok {
			return a.eapReject(in, ReasonBadCredentials, pkt.Identifier, eapTypePEAP, true)
		}
		user := rec.UserID
		if name != "" {
			user = name
		}
		if a.AAA == nil {
			crypto.Wipe(resp)
			return a.eapReject(in, ReasonInternal, pkt.Identifier, eapTypePEAP, true)
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
				Method:    domain.AuthMethodMSCHAPv2,
				CHAPID:    msID,
				Challenge: append([]byte(nil), rec.MD5Challenge...),
				Response:  resp,
			},
			Attributes: policySafeAttrs(in.Packet.Attributes),
		})
		crypto.Wipe(resp)
		if err != nil {
			if ctx != nil && ctx.Err() != nil {
				return Result{Action: ActionDiscard, Reason: ReasonOverload}
			}
			return a.eapReject(in, ReasonInternal, pkt.Identifier, eapTypePEAP, true)
		}
		if dec.Outcome != aaa.RadiusAccessAccept {
			_ = tun.WriteApp(peap.InnerFailure(pkt.Identifier))
			return a.eapReject(in, wireAccessReason(dec.ReasonCode), pkt.Identifier, eapTypePEAP, true)
		}
		if msg, ok := microsoftSuccessMessage(dec.ReplyAttributes); ok {
			_ = tun.WriteApp(peap.EncodeMSCHAPSuccess(pkt.Identifier+1, msID, msg))
		}
		if err := tun.WriteApp(peap.InnerSuccess(pkt.Identifier + 1)); err != nil {
			return a.eapReject(in, ReasonInternal, pkt.Identifier, eapTypePEAP, true)
		}
		rec.UserID = user
		return a.issuePEAPContinue(in, rec, firstFlight(tun, tun.PullServer()), runtime.StepPEAPFinish)
	default:
		return a.eapReject(in, ReasonInvalidState, pkt.Identifier, eapTypePEAP, true)
	}
}

func microsoftSuccessMessage(attrs attribute.RawSet) ([]byte, bool) {
	for _, raw := range attrs.AllOf(attribute.TypeVendorSpecific) {
		vsa, err := attribute.ParseVSA(raw)
		if err != nil || vsa.Vendor != attribute.VendorMicrosoft {
			continue
		}
		tlvs, err := attribute.ParseVendorTLVs(vsa.Payload)
		if err != nil {
			continue
		}
		for _, t := range tlvs {
			if t.Type == attribute.VendorTypeMSCHAP2Success && len(t.Value) > 1 {
				return append([]byte(nil), t.Value[1:]...), true
			}
		}
	}
	return nil, false
}

func (a Access) issuePEAPContinue(in Request, rec runtime.ChallengeRecord, body []byte, step runtime.ChallengeStep) Result {
	state, err := readRand(a.entropy(), eapStateLen)
	if err != nil {
		return a.eapReject(in, ReasonInternal, rec.EAPID, eapTypePEAP, true)
	}
	id := rec.EAPID + 1
	reason := IssueChallenge(a.Store, in, runtime.ChallengeIssue{
		State:        state,
		UserID:       rec.UserID,
		Method:       methodPEAP,
		EAPID:        id,
		EAPType:      eapTypePEAP,
		Step:         step,
		MD5Challenge: rec.MD5Challenge,
		TunnelID:     rec.TunnelID,
		EndpointID:   in.EndpointID,
		ClientID:     in.ClientID,
	})
	if reason != "" {
		crypto.Wipe(state)
		return a.eapReject(in, reason, rec.EAPID, eapTypePEAP, true)
	}
	a.noteChallenge(observability.ChallengeResultIssue)
	a.noteEAP(eapTypePEAP, true, observability.OutcomeAccessChallenge)
	if len(body) == 0 {
		body = peap.Encode(peap.Payload{Version: peap.Version0})
	}
	extra := attribute.RawSet{{Type: attribute.TypeState, Value: state}}
	extra = append(extra, eapMessageAttrs(encodeEAP(eapPacket{
		Code: eapCodeRequest, Identifier: id, Type: eapTypePEAP, HasType: true, Data: body,
	}))...)
	return replyAccess(in, codec.CodeAccessChallenge, ReasonChallenge, extra)
}

func tunnelIDFromState(state []byte) string {
	return hex.EncodeToString(state)
}
