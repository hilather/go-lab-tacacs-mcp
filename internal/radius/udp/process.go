package udp

import (
	"context"
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
	reasonUnknownClient    = server.ReasonUnknownClient
	reasonAmbiguousClient  = server.ReasonAmbiguousClient
	reasonOverload         = server.ReasonOverload
	reasonSecretMissing    = "secret_unavailable"
	reasonJournalSaturated = "journal_saturated"
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
	client, endpointID, err := snap.MatchRADIUS(l.role, domain.CarrierRADIUSUDP, ip)
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
	// Accounting integrity before any cache mutation. Invalid MA or
	// Request Authenticator must not read, insert, or purge a slot.
	if l.role == domain.RoleAccounting {
		if reason := server.CheckAccountingIntegrity(secret, body, pkt); reason != "" {
			l.note(reason)
			return
		}
	}

	requireMA, limitPS, methods := endpointAccessPolicy(client, endpointID)
	req := server.Request{
		Role:                        l.role,
		Carrier:                     domain.CarrierRADIUSUDP,
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
		Carrier:                     domain.CarrierRADIUSUDP,
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
		l.observeRetransmit(observability.RetransmitHitCompleted)
		l.writeTo(src, cached)
		return
	case LookupPending:
		l.observeRetransmit(observability.RetransmitHitPending)
		return
	case LookupSaturated:
		l.observeCacheSaturation()
		l.note(reasonOverload)
		return
	case LookupPurged:
		l.observeRetransmit(observability.RetransmitPurge)
	default:
		l.observeRetransmit(observability.RetransmitMiss)
	}

	req.Peer = peerAddrPort(src)
	req.AcceptStatusTypes = radiusAcceptStatusTypes(client, endpointID)
	req.Journal = l.journal
	req.Sampler = l.sampler
	start := l.now()
	res := l.handler.Handle(ctx, req)
	elapsed := l.now().Sub(start).Seconds()
	if res.JournalSaturated {
		l.setError(reasonJournalSaturated)
		if l.opts.Metrics != nil {
			l.opts.Metrics.RADIUSJournalSaturation(observability.RoleAccounting)
		}
	}
	if res.Action != server.ActionReply || len(res.Response) == 0 {
		l.cache.Abandon(key, fp)
		if res.Reason != "" {
			l.note(res.Reason)
		}
		l.observeCacheEntries()
		return
	}
	if res.Reason == server.ReasonAmbiguousIdentity {
		l.note(res.Reason)
	}
	l.cache.Complete(key, fp, res.Response)
	l.observeCacheEntries()
	l.observeRequest(pkt.Code, res, elapsed)
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

func radiusAcceptStatusTypes(client state.EffectiveClient, endpointID string) []string {
	for _, ep := range client.Client.Endpoints {
		if ep.ID == endpointID && ep.RADIUS != nil {
			return append([]string(nil), ep.RADIUS.AcceptStatusTypes...)
		}
	}
	return nil
}

func peerAddrPort(addr net.Addr) netip.AddrPort {
	if addr == nil {
		return netip.AddrPort{}
	}
	if a, ok := addr.(*net.UDPAddr); ok && a.IP != nil {
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
	if l.opts.Metrics == nil {
		return
	}
	l.opts.Metrics.ProtocolDiscard(observability.ProtocolRADIUS, observability.TransportUDP, l.metricRole(), reason)
	switch reason {
	case server.ReasonInvalidMA, server.ReasonMissingMA, server.ReasonEAPWithoutMA, server.ReasonProxyStateWithoutMA:
		l.opts.Metrics.RADIUSAuthenticatorFailure(l.metricRole(), observability.AuthTypeMessageAuthenticator)
	case server.ReasonInvalidAcctAuth:
		l.opts.Metrics.RADIUSAuthenticatorFailure(l.metricRole(), observability.AuthTypeAccountingRequest)
	}
}

func (l *Listener) observeRetransmit(result string) {
	if l.opts.Metrics != nil {
		l.opts.Metrics.RADIUSRetransmission(l.metricRole(), result)
	}
}

func (l *Listener) observeCacheSaturation() {
	if l.opts.Metrics != nil {
		l.opts.Metrics.RADIUSCacheSaturation(l.metricRole())
	}
}

func (l *Listener) observeCacheEntries() {
	if l.opts.Metrics != nil {
		l.opts.Metrics.RADIUSCacheEntries(l.metricRole(), l.cache.len())
	}
}

func (l *Listener) observeQueue() {
	if l.opts.Metrics != nil {
		l.opts.Metrics.RADIUSQueueDepth(l.metricRole(), int(l.queued.Load()))
	}
}

func (l *Listener) observeInflight() {
	if l.opts.Metrics != nil {
		l.opts.Metrics.RADIUSInflight(l.metricRole(), int(l.inflight.Load()))
	}
}

func (l *Listener) observeRequest(reqCode codec.Code, res server.Result, seconds float64) {
	if l.opts.Metrics == nil {
		return
	}
	code, outcome := replyLabels(reqCode, res)
	l.opts.Metrics.ProtocolRequest(observability.ProtocolRADIUS, observability.TransportUDP, l.metricRole(), code, outcome, seconds)
}

func (l *Listener) metricRole() string {
	if l.role == domain.RoleAccounting {
		return observability.RoleAccounting
	}
	return observability.RoleAccess
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

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
