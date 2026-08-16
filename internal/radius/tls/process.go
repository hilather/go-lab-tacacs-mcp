package tls

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	reasonUnknownClient   = server.ReasonUnknownClient
	reasonAmbiguousClient = server.ReasonAmbiguousClient
	reasonOverload        = server.ReasonOverload
	reasonSecretMissing   = "secret_unavailable"
)

type boundConn struct {
	client     state.EffectiveClient
	endpointID string
	secret     []byte
	srcKey     string
	peer       netip.AddrPort
	revision   domain.Revision
}

func (l *Listener) handleConn(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	hs := l.handshake
	if hs <= 0 {
		hs = 10 * time.Second
	}
	_ = nc.SetDeadline(l.now().Add(hs))
	tlsConn := tls.Server(nc, l.tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		l.note(reasonUnknownClient)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	cs := tlsConn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		l.note(reasonUnknownClient)
		return
	}
	leaf := cs.PeerCertificates[0]
	snap := l.opts.Snapshot()
	if snap == nil {
		l.note(reasonSecretMissing)
		return
	}
	ip := peerIP(tlsConn.RemoteAddr())
	client, endpointID, err := matchTLSClient(snap, ip, certIdentity(leaf))
	if err != nil {
		if isAmbiguous(err) {
			l.note(reasonAmbiguousClient)
			return
		}
		l.note(reasonUnknownClient)
		return
	}
	secret, err := lookupRADIUSSecret(l.opts.Secrets, client, endpointID)
	if err != nil || len(secret) == 0 {
		wipe(secret)
		l.note(reasonSecretMissing)
		return
	}
	defer wipe(secret)
	fp := certFingerprint(leaf)
	bound := boundConn{
		client:     client,
		endpointID: endpointID,
		secret:     secret,
		srcKey:     "tls:" + hex.EncodeToString(fp[:]),
		peer:       peerAddrPort(tlsConn.RemoteAddr()),
		revision:   snap.Revision,
	}
	for {
		if l.closed.Load() || ctx.Err() != nil {
			return
		}
		if l.idle > 0 {
			_ = tlsConn.SetDeadline(l.now().Add(l.idle))
		}
		body, err := ReadPacket(tlsConn, l.bounds.MaxPacketBytes)
		if err != nil {
			if err == io.EOF || errorsIsClosed(err) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return
			}
			l.note(codec.ReasonInvalidLength)
			return
		}
		l.inflight.Add(1)
		l.process(ctx, tlsConn, body, bound)
		l.inflight.Add(-1)
	}
}

func matchTLSClient(snap *state.Snapshot, ip net.IP, cert *config.CertIdentity) (state.EffectiveClient, string, error) {
	acc, accEP, accErr := snap.MatchRADIUSTLS(domain.RoleAccess, ip, cert)
	acct, acctEP, acctErr := snap.MatchRADIUSTLS(domain.RoleAccounting, ip, cert)
	if accErr == nil && acctErr == nil {
		if acc.Client.ID != acct.Client.ID || accEP != acctEP {
			return state.EffectiveClient{}, "", domain.NewError(domain.CodeClientMatchAmbiguous, "RADIUS TLS access and accounting matched different clients")
		}
		return acc, accEP, nil
	}
	if accErr == nil {
		return acc, accEP, nil
	}
	if acctErr == nil {
		return acct, acctEP, nil
	}
	if isAmbiguous(accErr) {
		return state.EffectiveClient{}, "", accErr
	}
	if isAmbiguous(acctErr) {
		return state.EffectiveClient{}, "", acctErr
	}
	return state.EffectiveClient{}, "", accErr
}

func (l *Listener) process(ctx context.Context, w io.Writer, body []byte, bound boundConn) {
	pkt, err := codec.DecodeBounded(body, l.bounds)
	if err != nil {
		l.note(codec.DiscardReason(err))
		return
	}
	role, ok := roleForCode(pkt.Code)
	if !ok || !endpointHasRole(bound.client, bound.endpointID, role) {
		l.note(server.ReasonInvalidCode)
		return
	}
	if role == domain.RoleAccounting {
		if reason := server.CheckAccountingIntegrity(bound.secret, body, pkt); reason != "" {
			l.note(reason)
			return
		}
	}
	requireMA, limitPS, methods := endpointAccessPolicy(bound.client, bound.endpointID)
	req := server.Request{
		Role:                        role,
		Carrier:                     domain.CarrierRADIUSTLS,
		Packet:                      pkt,
		Declared:                    body,
		Secret:                      bound.secret,
		ClientID:                    bound.client.Client.ID,
		EndpointID:                  bound.endpointID,
		ListenerID:                  l.ID(),
		Revision:                    bound.revision,
		Peer:                        bound.peer,
		RequireMessageAuthenticator: requireMA,
		LimitProxyState:             limitPS,
		AllowedMethods:              methods,
		AcceptStatusTypes:           radiusAcceptStatusTypes(bound.client, bound.endpointID),
		Journal:                     l.journal,
		Sampler:                     l.sampler,
	}
	if reason := server.CheckIntegrity(req); reason != "" {
		l.note(reason)
		return
	}
	key := slotKey{
		endpointID: bound.endpointID,
		role:       role,
		src:        bound.srcKey,
		listenerID: l.ID(),
		code:       pkt.Code,
		id:         pkt.Identifier,
	}
	fp := fingerprintOf(body)
	switch got, cached := l.cache.Begin(key, fp); got {
	case lookupHit:
		_ = WritePacket(w, cached)
		return
	case lookupPending:
		return
	case lookupSaturated:
		l.note(reasonOverload)
		return
	}
	handler := l.access
	if role == domain.RoleAccounting {
		handler = l.accounting
	}
	start := l.now()
	res := handler.Handle(ctx, req)
	elapsed := l.now().Sub(start).Seconds()
	if res.Action != server.ActionReply || len(res.Response) == 0 {
		l.cache.Abandon(key, fp)
		if res.Reason != "" {
			l.note(res.Reason)
		}
		return
	}
	l.cache.Complete(key, fp, res.Response)
	l.observeRequest(pkt.Code, res, elapsed)
	if err := WritePacket(w, res.Response); err != nil {
		l.setError("send")
	}
}

func roleForCode(code codec.Code) (domain.ListenerRole, bool) {
	switch code {
	case codec.CodeAccessRequest:
		return domain.RoleAccess, true
	case codec.CodeAccountingRequest:
		return domain.RoleAccounting, true
	default:
		return "", false
	}
}

func endpointHasRole(client state.EffectiveClient, endpointID string, role domain.ListenerRole) bool {
	for _, ep := range client.Client.Endpoints {
		if ep.ID != endpointID {
			continue
		}
		for _, r := range ep.Roles {
			if r == role {
				return true
			}
		}
	}
	return false
}

func endpointAccessPolicy(client state.EffectiveClient, endpointID string) (requireMA, limitPS bool, methods []string) {
	requireMA = true
	limitPS = true
	for _, ep := range client.Client.Endpoints {
		if ep.ID != endpointID || ep.RADIUS == nil {
			continue
		}
		return ep.RADIUS.RequireMessageAuthenticator, ep.RADIUS.LimitProxyState, append([]string(nil), ep.RADIUS.AllowedAuthenticationMethods...)
	}
	return requireMA, limitPS, nil
}

func radiusAcceptStatusTypes(client state.EffectiveClient, endpointID string) []string {
	for _, ep := range client.Client.Endpoints {
		if ep.ID == endpointID && ep.RADIUS != nil {
			return append([]string(nil), ep.RADIUS.AcceptStatusTypes...)
		}
	}
	return nil
}

func lookupRADIUSSecret(lookup config.SecretLookup, client state.EffectiveClient, endpointID string) ([]byte, error) {
	for _, ep := range client.Client.Endpoints {
		if ep.ID != endpointID || ep.RADIUS == nil {
			continue
		}
		return lookup(ep.RADIUS.SharedSecret)
	}
	return nil, domain.NewError(domain.CodeRADIUSSecretMissing, "RADIUS endpoint secret is not configured")
}

func peerAddrPort(addr net.Addr) netip.AddrPort {
	if addr == nil {
		return netip.AddrPort{}
	}
	if a, ok := addr.(*net.TCPAddr); ok && a.IP != nil {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return netip.AddrPort{}
		}
		if v4 := a.IP.To4(); v4 != nil {
			ip = netip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]})
		}
		return netip.AddrPortFrom(ip, uint16(a.Port))
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return ap
}

func isAmbiguous(err error) bool {
	de, ok := domain.AsError(err)
	return ok && de.Code == domain.CodeClientMatchAmbiguous
}

func errorsIsClosed(err error) bool {
	return err != nil && (err == net.ErrClosed || err == io.ErrUnexpectedEOF)
}

func (l *Listener) note(reason string) {
	if reason == "" {
		return
	}
	l.setError(reason)
	l.opts.Logger.Debug("radius tls discard", "listener", l.ID(), "reason", reason)
	if l.opts.Metrics == nil {
		return
	}
	l.opts.Metrics.ProtocolDiscard(observability.ProtocolRADIUS, observability.TransportTLS, observability.RoleAccess, reason)
}

func (l *Listener) observeRequest(reqCode codec.Code, res server.Result, seconds float64) {
	if l.opts.Metrics == nil {
		return
	}
	code, outcome := replyLabels(reqCode, res)
	l.opts.Metrics.ProtocolRequest(observability.ProtocolRADIUS, observability.TransportTLS, observability.RoleAccess, code, outcome, seconds)
}

func (l *Listener) now() time.Time {
	if l.opts.Now != nil {
		return l.opts.Now()
	}
	return time.Now()
}

func replyLabels(req codec.Code, res server.Result) (code, outcome string) {
	if req == codec.CodeAccountingRequest {
		return observability.CodeAccountingResponse, observability.OutcomeOK
	}
	if res.Reason == server.ReasonOK {
		return observability.CodeAccessAccept, observability.OutcomeAccessAccept
	}
	return observability.CodeAccessReject, observability.OutcomeAccessReject
}
