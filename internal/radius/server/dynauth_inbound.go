package server

import (
	"context"
	"encoding/binary"
	"net/netip"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

// DynamicAuth is the inbound DAS echo fixture. It mutates SessionIndex only
// and never forwards a packet to a NAS.
type DynamicAuth struct {
	Sessions *radiusruntime.SessionIndex
	Metrics  *observability.Recorder
}

// Handle implements Handler for CoA-Request and Disconnect-Request.
func (d DynamicAuth) Handle(ctx context.Context, in Request) Result {
	if ctx != nil && ctx.Err() != nil {
		return Result{Action: ActionDiscard, Reason: ReasonOverload}
	}
	if in.Role != domain.RoleDynamicAuthorization {
		return Result{Action: ActionDiscard, Reason: ReasonInvalidCode}
	}
	switch in.Packet.Code {
	case codec.CodeCoARequest, codec.CodeDisconnectRequest:
	default:
		return Result{Action: ActionDiscard, Reason: ReasonInvalidCode}
	}
	if reason := CheckIntegrity(in); reason != "" {
		return Result{Action: ActionDiscard, Reason: reason}
	}

	attrs := in.Packet.Attributes
	if err := attribute.Builtin().CheckSet(attrs, uint8(in.Packet.Code)); err != nil {
		return d.replyNAK(in, ReasonUnsupportedAttribute, ErrorCauseUnsupportedAttribute)
	}
	if unsupported := firstUnsupportedDynAuthAttr(in.Packet.Code, attrs); unsupported {
		return d.replyNAK(in, ReasonUnsupportedAttribute, ErrorCauseUnsupportedAttribute)
	}

	rec, n := d.lookup(in, attrs)
	if n == 0 {
		return d.replyNAK(in, ReasonSessionNotFound, ErrorCauseSessionContextNotFound)
	}
	if n > 1 {
		return d.replyNAK(in, ReasonMultipleSessions, ErrorCauseMultipleSessionSelection)
	}

	switch in.Packet.Code {
	case codec.CodeDisconnectRequest:
		_ = d.Sessions.Delete(rec.Key)
		return d.replyACK(in, ReasonOK)
	default:
		d.Sessions.StoreLastCoA(rec.Key, lastCoAFrom(attrs))
		return d.replyACK(in, ReasonOK)
	}
}

func (d DynamicAuth) lookup(in Request, attrs attribute.RawSet) (radiusruntime.SessionRecord, int) {
	if d.Sessions == nil {
		return radiusruntime.SessionRecord{}, 0
	}
	q := radiusruntime.DASQuery{ClientID: in.ClientID}
	if a, ok := attrs.First(attribute.TypeAcctSessionID); ok {
		q.SessionID = string(a.Value)
	}
	if a, ok := attrs.First(attribute.TypeUserName); ok {
		q.UserID = string(a.Value)
	}
	if a, ok := attrs.First(attribute.TypeNASIPAddress); ok && len(a.Value) == 4 {
		q.NASIP = netip.AddrFrom4([4]byte{a.Value[0], a.Value[1], a.Value[2], a.Value[3]})
	}
	if a, ok := attrs.First(attribute.TypeNASIdentifier); ok {
		q.NASIdentifier = string(a.Value)
	}
	if q.SessionID == "" && q.UserID == "" {
		return radiusruntime.SessionRecord{}, 0
	}
	return d.Sessions.FindDAS(q)
}

func firstUnsupportedDynAuthAttr(code codec.Code, attrs attribute.RawSet) bool {
	for _, a := range attrs {
		if !dynAuthAttrAllowed(code, a.Type) {
			return true
		}
	}
	return false
}

func dynAuthAttrAllowed(code codec.Code, typ uint8) bool {
	switch typ {
	case attribute.TypeMessageAuthenticator, attribute.TypeUserName, attribute.TypeNASIPAddress,
		attribute.TypeNASIPv6Address, attribute.TypeNASIdentifier, attribute.TypeNASPort,
		attribute.TypeAcctSessionID, attribute.TypeClass, attribute.TypeEventTimestamp,
		attribute.TypeProxyState:
		return true
	case attribute.TypeSessionTimeout, attribute.TypeIdleTimeout, attribute.TypeReplyMessage:
		return code == codec.CodeCoARequest
	default:
		return false
	}
}

func lastCoAFrom(attrs attribute.RawSet) radiusruntime.LastCoA {
	var out radiusruntime.LastCoA
	if a, ok := attrs.First(attribute.TypeSessionTimeout); ok && len(a.Value) == 4 {
		v := binary.BigEndian.Uint32(a.Value)
		out.SessionTimeout = &v
	}
	if a, ok := attrs.First(attribute.TypeIdleTimeout); ok && len(a.Value) == 4 {
		v := binary.BigEndian.Uint32(a.Value)
		out.IdleTimeout = &v
	}
	for _, a := range attrs.AllOf(attribute.TypeReplyMessage) {
		out.ReplyMessage = append(out.ReplyMessage, string(a.Value))
	}
	return out
}

func (d DynamicAuth) replyACK(in Request, reason string) Result {
	code := codec.CodeCoAACK
	if in.Packet.Code == codec.CodeDisconnectRequest {
		code = codec.CodeDisconnectACK
	}
	return d.reply(in, code, reason, nil)
}

func (d DynamicAuth) replyNAK(in Request, reason string, cause uint32) Result {
	code := codec.CodeCoANAK
	if in.Packet.Code == codec.CodeDisconnectRequest {
		code = codec.CodeDisconnectNAK
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], cause)
	return d.reply(in, code, reason, attribute.RawSet{{Type: attribute.TypeErrorCause, Value: raw[:]}})
}

func (d DynamicAuth) reply(in Request, code codec.Code, reason string, extra attribute.RawSet) Result {
	rest := CopyProxyState(in.Packet.Attributes)
	if extra.Len() > 0 {
		rest = append(rest, extra...)
	}
	wire, err := SignResponse(in.Secret, code, in.Packet.Identifier, in.Packet.Authenticator, rest)
	if err != nil {
		return Result{Action: ActionDiscard, Reason: ReasonMalformedHeader}
	}
	d.observe(in.Packet.Code, reasonToOutcome(reason, code))
	return Result{Action: ActionReply, Reason: reason, Response: wire}
}

func (d DynamicAuth) observe(req codec.Code, outcome string) {
	if d.Metrics == nil {
		return
	}
	name := observability.CodeCoARequest
	if req == codec.CodeDisconnectRequest {
		name = observability.CodeDisconnectRequest
	}
	d.Metrics.RADIUSDynAuth(observability.DirectionIn, name, outcome)
}

func reasonToOutcome(reason string, code codec.Code) string {
	switch code {
	case codec.CodeCoAACK, codec.CodeDisconnectACK:
		return observability.OutcomeACK
	case codec.CodeCoANAK, codec.CodeDisconnectNAK:
		return observability.OutcomeNAK
	default:
		if reason == ReasonOK {
			return observability.OutcomeACK
		}
		return observability.OutcomeNAK
	}
}
