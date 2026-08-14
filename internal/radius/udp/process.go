package udp

import (
	"context"
	"net"
	"net/netip"

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

// serverReasonOverload is used by the receive loop (no process import cycle).
const serverReasonOverload = server.ReasonOverload

func (l *Listener) process(ctx context.Context, buf []byte, src net.Addr) {
	if len(buf) < codec.HeaderSize {
		l.note(codec.ReasonMalformedHeader)
		return
	}
	h, err := codec.DecodeHeader(buf)
	if err != nil {
		l.note(codec.DiscardReason(err))
		return
	}
	declared := int(h.Length)
	if declared < codec.MinPacketBytes || declared > l.bounds.MaxPacketBytes || declared > len(buf) {
		l.note(codec.ReasonInvalidLength)
		return
	}
	body := buf[:declared]

	snap := l.opts.Snapshot()
	if snap == nil {
		l.note(reasonSecretMissing)
		return
	}
	ip := peerIP(src)
	// Source → compiled RADIUSIndex before any secret or crypto work.
	client, endpointID, err := snap.MatchRADIUS(l.role, ip)
	if err != nil {
		if isAmbiguous(err) {
			l.note(reasonAmbiguousClient)
			return
		}
		l.note(reasonUnknownClient)
		return
	}

	srcKey := src.String()
	if !l.limit.Allow(srcKey) {
		l.note(reasonOverload)
		return
	}

	secret, err := lookupRADIUSSecret(l.opts.Secrets, client, endpointID)
	if err != nil || len(secret) == 0 {
		wipe(secret)
		l.note(reasonSecretMissing)
		return
	}
	defer wipe(secret)

	pkt, err := codec.DecodeBounded(body, l.bounds)
	if err != nil {
		l.note(codec.DiscardReason(err))
		return
	}
	if !codeAllowed(l.role, pkt.Code) {
		l.note(server.ReasonInvalidCode)
		return
	}

	requireMA, limitPS, methods := endpointAccessPolicy(client, endpointID)
	req := server.Request{
		Role:                        l.role,
		Packet:                      pkt,
		Declared:                    body,
		Secret:                      secret,
		ClientID:                    client.Client.ID,
		EndpointID:                  endpointID,
		ListenerID:                  l.id,
		Revision:                    snap.Revision,
		RequireMessageAuthenticator: requireMA,
		LimitProxyState:             limitPS,
		AllowedMethods:              methods,
	}
	// Invalid MA must not read, insert, or purge the retransmission cache.
	if reason := server.CheckIntegrity(req); reason != "" {
		l.note(reason)
		return
	}

	key := slotKey{
		endpointID: endpointID,
		role:       l.role,
		src:        srcKey,
		listenerID: l.id,
		code:       pkt.Code,
		id:         pkt.Identifier,
	}
	fp := fingerprintOf(body)
	switch got, cached := l.cache.Begin(key, fp); got {
	case LookupHit:
		l.writeTo(src, cached)
		return
	case LookupPending:
		return
	case LookupSaturated:
		l.note(reasonOverload)
		return
	}

	res := l.handler.Handle(ctx, req)
	if res.Action != server.ActionReply || len(res.Response) == 0 {
		l.cache.Abandon(key, fp)
		if res.Reason != "" {
			l.note(res.Reason)
		}
		return
	}
	l.cache.Complete(key, fp, res.Response)
	l.writeTo(src, res.Response)
}

func codeAllowed(role domain.ListenerRole, code codec.Code) bool {
	switch role {
	case domain.RoleAccess:
		return code == codec.CodeAccessRequest
	case domain.RoleAccounting:
		return code == codec.CodeAccountingRequest
	default:
		return false
	}
}

func isAmbiguous(err error) bool {
	de, ok := domain.AsError(err)
	return ok && de.Code == domain.CodeClientMatchAmbiguous
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

func lookupRADIUSSecret(lookup config.SecretLookup, client state.EffectiveClient, endpointID string) ([]byte, error) {
	for _, ep := range client.Client.Endpoints {
		if ep.ID != endpointID || ep.RADIUS == nil {
			continue
		}
		return lookup(ep.RADIUS.SharedSecret)
	}
	return nil, domain.NewError(domain.CodeRADIUSSecretMissing, "RADIUS endpoint secret is not configured")
}

func peerIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if a, ok := addr.(*net.UDPAddr); ok {
		return a.IP
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		host, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			return net.ParseIP(addr.String())
		}
		return net.ParseIP(host)
	}
	ip := ap.Addr()
	if ip.Is4() {
		b := ip.As4()
		return net.IP(b[:])
	}
	b := ip.As16()
	return net.IP(b[:])
}

func (l *Listener) writeTo(src net.Addr, payload []byte) {
	if l.pc == nil || len(payload) == 0 {
		return
	}
	if _, err := l.pc.WriteTo(payload, src); err != nil {
		l.setError("send")
	}
}

func (l *Listener) note(reason string) {
	if reason == "" {
		return
	}
	l.setError(reason)
	l.opts.Logger.Debug("radius discard", "listener", l.id, "reason", reason)
	if l.opts.Metrics != nil {
		l.opts.Metrics.ProtocolError(metricListener(l.id), observability.TransportUDP, metricCode(reason))
	}
}

func metricListener(id string) string {
	if id == observability.ListenerRADIUSAccounting {
		return observability.ListenerRADIUSAccounting
	}
	return observability.ListenerRADIUSAccess
}

func metricCode(reason string) string {
	switch reason {
	case reasonUnknownClient, reasonAmbiguousClient:
		return "unknown_client"
	case reasonSecretMissing:
		return "secret_unavailable"
	case reasonOverload:
		return "rate_limited"
	default:
		return "protocol"
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
