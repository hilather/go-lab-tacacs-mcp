package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

const (
	// DynAuthOutcomeACK is a CoA/Disconnect-ACK.
	DynAuthOutcomeACK = "ack"
	// DynAuthOutcomeNAK is a CoA/Disconnect-NAK.
	DynAuthOutcomeNAK = "nak"
	// DynAuthOutcomeTimeout means no reply within coa_timeout.
	DynAuthOutcomeTimeout = "timeout"

	defaultCoATimeout = 3 * time.Second
	originateCacheTTL = 15 * time.Second
	maxOriginateCache = 256
	defaultNASCoAPort = 3799
)

// OriginateRequest is one DAC datagram. Secret is wiped by the caller.
type OriginateRequest struct {
	Secret      []byte
	Destination string
	Code        codec.Code
	Attributes  attribute.RawSet
	Timeout     time.Duration
	CacheKey    string
}

// OriginateResult is the DAC outcome. Timeout is not an overlay error.
type OriginateResult struct {
	Outcome    string
	ErrorCause uint32
	Code       codec.Code
}

// Originator sends RFC 5176 CoA/Disconnect requests. MA is required.
type Originator struct {
	Clock domain.Clock
	// Entropy is retained for source compatibility; RFC 5176 request checksums do not use randomness.
	Entropy io.Reader
	Dial    func(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error)
	Metrics *observability.Recorder

	mu    sync.Mutex
	cache map[string]originateEntry
}

type originateEntry struct {
	wire     []byte
	reqAuth  [16]byte
	deadline time.Time
}

// SignDynAuthRequest builds an RFC 5176 CoA/Disconnect-Request with MA first.
// The legacy authenticator argument is ignored: the request checksum is derived.
func SignDynAuthRequest(secret []byte, code codec.Code, id uint8, _ [16]byte, rest attribute.RawSet) ([]byte, error) {
	if code != codec.CodeCoARequest && code != codec.CodeDisconnectRequest {
		return nil, domain.NewError(domain.CodeInvalidArgument, "dynauth request code must be CoA-Request or Disconnect-Request")
	}
	attrs := make(attribute.RawSet, 0, 1+rest.Len())
	attrs = append(attrs, attribute.Raw{
		Type:  attribute.TypeMessageAuthenticator,
		Value: make([]byte, codec.AuthenticatorSize),
	})
	attrs = append(attrs, rest...)
	if err := attribute.Builtin().CheckSet(attrs, uint8(code)); err != nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "illegal dynauth attribute set").WithDetail("err", err.Error())
	}
	wire, err := codec.Encode(codec.Packet{
		Code:          code,
		Identifier:    id,
		Authenticator: [16]byte{},
		Attributes:    attrs,
	})
	if err != nil {
		return nil, err
	}
	mac, err := crypto.DynAuthMessageAuthenticator(secret, wire)
	if err != nil {
		return nil, err
	}
	off := codec.HeaderSize
	if len(wire) < off+2+codec.AuthenticatorSize || wire[off] != attribute.TypeMessageAuthenticator {
		return nil, crypto.ErrInvalidMessageAuthenticator
	}
	copy(wire[off+2:off+18], mac[:])
	auth, err := crypto.DynAuthRequestAuthenticator(secret, wire)
	if err != nil {
		return nil, err
	}
	copy(wire[4:20], auth[:])
	return wire, nil
}

// Send writes one datagram and waits for ACK/NAK/timeout. No automatic retry.
func (o *Originator) Send(ctx context.Context, req OriginateRequest) (OriginateResult, error) {
	if ctx != nil && ctx.Err() != nil {
		return OriginateResult{}, ctx.Err()
	}
	if len(req.Secret) == 0 {
		return OriginateResult{}, domain.NewError(domain.CodeRADIUSSecretMissing, "RADIUS shared secret is not configured")
	}
	if req.Destination == "" {
		return OriginateResult{}, domain.NewError(domain.CodeInvalidArgument, "destination is required").WithPath("destination")
	}
	if req.Code != codec.CodeCoARequest && req.Code != codec.CodeDisconnectRequest {
		return OriginateResult{}, domain.NewError(domain.CodeInvalidArgument, "dynauth request code must be CoA-Request or Disconnect-Request")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultCoATimeout
	}
	now := time.Now()
	if o != nil && o.Clock != nil {
		now = o.Clock.Now()
	}
	if wire, auth, ok := o.cached(req.CacheKey, now); ok {
		return o.exchange(ctx, req.Secret, req.Destination, req.Code, wire, auth, timeout)
	}

	id := uint8(now.UnixNano())
	wire, err := SignDynAuthRequest(req.Secret, req.Code, id, [16]byte{}, req.Attributes)
	if err != nil {
		return OriginateResult{}, err
	}
	var reqAuth [16]byte
	copy(reqAuth[:], wire[4:20])
	o.remember(req.CacheKey, wire, reqAuth, now.Add(originateCacheTTL))
	return o.exchange(ctx, req.Secret, req.Destination, req.Code, wire, reqAuth, timeout)
}

func (o *Originator) exchange(ctx context.Context, secret []byte, dest string, reqCode codec.Code, wire []byte, reqAuth [16]byte, timeout time.Duration) (OriginateResult, error) {
	dial := defaultDial
	if o != nil && o.Dial != nil {
		dial = o.Dial
	}
	if ctx == nil {
		ctx = context.Background()
	}
	conn, addr, err := dial(ctx, "udp", dest)
	if err != nil {
		return OriginateResult{}, domain.NewError(domain.CodeInvalidArgument, "dynauth destination is not reachable").WithPath("destination")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return OriginateResult{}, err
	}
	if _, err := conn.WriteTo(wire, addr); err != nil {
		return OriginateResult{}, err
	}
	buf := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return OriginateResult{}, err
		}
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return OriginateResult{}, ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				o.observe(reqCode, DynAuthOutcomeTimeout)
				return OriginateResult{Outcome: DynAuthOutcomeTimeout}, nil
			}
			return OriginateResult{}, err
		}
		remote, ok := peer.(*net.UDPAddr)
		if !ok || remote.Port != addr.Port || remote.Zone != addr.Zone || !remote.IP.Equal(addr.IP) {
			continue
		}
		pkt := buf[:n]
		h, err := codec.DecodeHeader(pkt)
		if err != nil || h.Identifier != wire[1] {
			continue
		}
		ack, nak := codec.CodeCoAACK, codec.CodeCoANAK
		if reqCode == codec.CodeDisconnectRequest {
			ack, nak = codec.CodeDisconnectACK, codec.CodeDisconnectNAK
		}
		if h.Code != ack && h.Code != nak {
			continue
		}
		forMA := append([]byte(nil), pkt...)
		copy(forMA[4:20], reqAuth[:])
		if crypto.ValidateMessageAuthenticator(secret, forMA) != nil || crypto.ValidateResponseAuthenticator(secret, pkt, reqAuth) != nil {
			continue
		}
		out := OriginateResult{Code: h.Code, Outcome: DynAuthOutcomeACK}
		if h.Code == nak {
			out.Outcome = DynAuthOutcomeNAK
			out.ErrorCause = errorCauseOf(pkt)
		}
		o.observe(reqCode, out.Outcome)
		return out, nil
	}
}

func (o *Originator) observe(code codec.Code, outcome string) {
	if o == nil || o.Metrics == nil {
		return
	}
	name := observability.CodeCoARequest
	if code == codec.CodeDisconnectRequest {
		name = observability.CodeDisconnectRequest
	}
	o.Metrics.RADIUSDynAuth(observability.DirectionOut, name, outcome)
}

func (o *Originator) cached(key string, now time.Time) ([]byte, [16]byte, bool) {
	if o == nil || key == "" {
		return nil, [16]byte{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.purgeLocked(now)
	ent, ok := o.cache[key]
	if !ok || now.After(ent.deadline) {
		return nil, [16]byte{}, false
	}
	return append([]byte(nil), ent.wire...), ent.reqAuth, true
}

func (o *Originator) remember(key string, wire []byte, auth [16]byte, until time.Time) {
	if o == nil || key == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cache == nil {
		o.cache = map[string]originateEntry{}
	}
	if len(o.cache) >= maxOriginateCache {
		return
	}
	o.cache[key] = originateEntry{wire: append([]byte(nil), wire...), reqAuth: auth, deadline: until}
}

func (o *Originator) purgeLocked(now time.Time) {
	for k, ent := range o.cache {
		if !ent.deadline.After(now) {
			delete(o.cache, k)
		}
	}
}

func defaultDial(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error) {
	_ = ctx
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, err
	}
	return conn, addr, nil
}

func errorCauseOf(packet []byte) uint32 {
	_, declared, err := decodeDeclared(packet)
	if err != nil {
		return 0
	}
	attrs, err := attribute.Decode(declared[codec.HeaderSize:], 0, 0)
	if err != nil {
		return 0
	}
	a, ok := attrs.First(attribute.TypeErrorCause)
	if !ok || len(a.Value) != 4 {
		return 0
	}
	return uint32(a.Value[0])<<24 | uint32(a.Value[1])<<16 | uint32(a.Value[2])<<8 | uint32(a.Value[3])
}

func decodeDeclared(packet []byte) (codec.Header, []byte, error) {
	h, err := codec.DecodeHeader(packet)
	if err != nil {
		return codec.Header{}, nil, err
	}
	if int(h.Length) > len(packet) {
		return codec.Header{}, nil, codec.ErrInvalidLength
	}
	return h, packet[:h.Length], nil
}

const (
	// ErrorCauseUnsupportedAttribute is RFC 5176 Error-Cause 401.
	ErrorCauseUnsupportedAttribute = 401
	// ErrorCauseSessionContextNotFound is RFC 5176 Error-Cause 503.
	ErrorCauseSessionContextNotFound = 503
	// ErrorCauseMultipleSessionSelection is RFC 5176 Error-Cause 508.
	ErrorCauseMultipleSessionSelection = 508
)

// DefaultNASCoAPort is used when the UDP endpoint omits nas_coa_port.
func DefaultNASCoAPort() uint16 { return defaultNASCoAPort }

// DefaultCoATimeout is the DAC wait when the listener omits coa_timeout.
func DefaultCoATimeout() time.Duration { return defaultCoATimeout }
