package operations

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	defaultSessionPage = 100
	maxSessionPage     = 500
)

func handleRadiusSessionsList(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if snap == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
		}
		req, _ := in.Request.(ListRadiusSessionsRequest)
		limit := req.Limit
		if limit <= 0 {
			limit = defaultSessionPage
		}
		if limit > maxSessionPage {
			limit = maxSessionPage
		}
		idx := deps.RADIUSSessions
		if idx == nil {
			return RadiusSessionList{Items: []RadiusSessionView{}}, nil
		}
		sensitive := hasScope(in.Actor, scopeEventsSensitive)
		page := idx.List(req.Cursor, limit+1)
		out := RadiusSessionList{Items: make([]RadiusSessionView, 0, limit)}
		for i, rec := range page {
			if i == limit {
				c := rec.Handle
				out.NextCursor = &c
				break
			}
			out.Items = append(out.Items, viewSession(rec, sensitive))
		}
		return out, nil
	}
}

func viewSession(rec radiusruntime.SessionRecord, sensitive bool) RadiusSessionView {
	v := RadiusSessionView{
		SessionHandle: rec.Handle,
		ClientID:      rec.ClientID,
		UserID:        rec.UserID,
		EndpointID:    rec.EndpointID,
		NASIdentifier: rec.NASIdentifier,
		NASPort:       rec.NASPort,
	}
	if rec.NASIP.IsValid() {
		v.NASIP = rec.NASIP.String()
	}
	if rec.Peer.IsValid() {
		v.Peer = rec.Peer.String()
	}
	if !rec.StartedAt.IsZero() {
		v.StartedAt = rec.StartedAt.UTC().Format(time.RFC3339)
	}
	if !rec.LastUpdate.IsZero() {
		v.LastUpdate = rec.LastUpdate.UTC().Format(time.RFC3339)
	}
	if sensitive {
		v.AcctSessionID = rec.Key.AcctSessionID
	}
	return v
}

func handleRadiusDisconnectSend(deps Deps) handleFunc {
	return handleDynAuthSend(deps, codec.CodeDisconnectRequest)
}

func handleRadiusCoASend(deps Deps) handleFunc {
	return handleDynAuthSend(deps, codec.CodeCoARequest)
}

func handleDynAuthSend(deps Deps, code codec.Code) handleFunc {
	return func(ctx context.Context, snap *state.Snapshot, in Input) (any, error) {
		if in.ExpectedRevision != nil {
			return nil, domain.NewError(domain.CodeInvalidArgument, "expected_revision is not accepted on dynauth originate").
				WithPath("expected_revision")
		}
		if snap == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
		}
		req, _ := in.Request.(RadiusDynamicAuthRequest)
		handleSet := strings.TrimSpace(req.SessionHandle) != ""
		explicitSet := strings.TrimSpace(req.ClientID) != ""
		if handleSet == explicitSet {
			return nil, domain.NewError(domain.CodeInvalidArgument, "exactly one of session_handle or client_id is required")
		}
		if deps.Originator == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "dynauth originator is not configured")
		}

		var (
			clientID string
			userID   string
			acctSess string
			nasIP    netip.Addr
			nasID    string
			nasPort  uint32
			dest     string
			cacheKey string
			timeout  time.Duration
		)
		if handleSet {
			if deps.RADIUSSessions == nil {
				return nil, domain.NewError(domain.CodeNotFound, "session not found").WithPath("session_handle")
			}
			rec, ok := deps.RADIUSSessions.LookupHandle(strings.TrimSpace(req.SessionHandle))
			if !ok {
				return nil, domain.NewError(domain.CodeNotFound, "session not found").WithPath("session_handle")
			}
			clientID = rec.ClientID
			userID = rec.UserID
			acctSess = rec.Key.AcctSessionID
			nasIP = rec.NASIP
			nasID = rec.NASIdentifier
			nasPort = rec.NASPort
			ep, secret, err := udpRADIUSSecret(snap, deps, clientID)
			if err != nil {
				return nil, err
			}
			defer wipeBytes(secret)
			dest, err = destFromHandle(ep, rec)
			if err != nil {
				return nil, err
			}
			timeout = snapCoATimeout(snap)
			cacheKey = "h:" + rec.Handle
			attrs, err := dynAuthAttrs(code, userID, acctSess, nasIP, nasID, nasPort, req.Attributes)
			if err != nil {
				return nil, err
			}
			res, err := deps.Originator.Send(ctx, server.OriginateRequest{
				Secret:      secret,
				Destination: dest,
				Code:        code,
				Attributes:  attrs,
				Timeout:     timeout,
				CacheKey:    cacheKey,
			})
			if err != nil {
				return nil, err
			}
			audit(deps, "api.radius.dynauth", res.Outcome, snap.Revision)
			return RadiusDynamicAuthResult{Outcome: res.Outcome, ErrorCause: res.ErrorCause}, nil
		}

		clientID = strings.TrimSpace(req.ClientID)
		if _, ok := snap.Client(clientID); !ok {
			return nil, domain.NewError(domain.CodeNotFound, "client not found").WithPath("client_id")
		}
		ep, secret, err := udpRADIUSSecret(snap, deps, clientID)
		if err != nil {
			return nil, err
		}
		defer wipeBytes(secret)
		dest = strings.TrimSpace(req.Destination)
		if dest == "" && ep.RADIUS != nil {
			dest = strings.TrimSpace(ep.RADIUS.CoADestination)
		}
		if dest == "" {
			return nil, domain.NewError(domain.CodeInvalidArgument, "destination is required unless the UDP endpoint sets coa_destination").
				WithPath("destination")
		}
		if _, _, err := net.SplitHostPort(dest); err != nil {
			return nil, domain.NewError(domain.CodeInvalidArgument, "destination must be host:port").WithPath("destination")
		}
		userID = strings.TrimSpace(req.UserID)
		acctSess = strings.TrimSpace(req.AcctSessionID)
		timeout = snapCoATimeout(snap)
		cacheKey = "e:" + clientID + "|" + dest + "|" + userID + "|" + acctSess
		attrs, err := dynAuthAttrs(code, userID, acctSess, netip.Addr{}, "", 0, req.Attributes)
		if err != nil {
			return nil, err
		}
		res, err := deps.Originator.Send(ctx, server.OriginateRequest{
			Secret:      secret,
			Destination: dest,
			Code:        code,
			Attributes:  attrs,
			Timeout:     timeout,
			CacheKey:    cacheKey,
		})
		if err != nil {
			return nil, err
		}
		audit(deps, "api.radius.dynauth", res.Outcome, snap.Revision)
		return RadiusDynamicAuthResult{Outcome: res.Outcome, ErrorCause: res.ErrorCause}, nil
	}
}

func udpRADIUSSecret(snap *state.Snapshot, deps Deps, clientID string) (config.ClientEndpoint, []byte, error) {
	c, ok := snap.Client(clientID)
	if !ok {
		return config.ClientEndpoint{}, nil, domain.NewError(domain.CodeNotFound, "client not found").WithPath("client_id")
	}
	ep := config.RADIUSUDPEndpoint(c.Client)
	if ep == nil || ep.RADIUS == nil {
		return config.ClientEndpoint{}, nil, domain.NewError(domain.CodeRADIUSSecretMissing, "client has no UDP RADIUS endpoint").
			WithPath("client_id")
	}
	if !ep.RADIUS.SharedSecret.Set() {
		return config.ClientEndpoint{}, nil, domain.NewError(domain.CodeRADIUSSecretMissing, "RADIUS shared secret is not configured").
			WithPath("client_id")
	}
	if deps.Secrets == nil {
		return config.ClientEndpoint{}, nil, domain.NewError(domain.CodeRADIUSSecretMissing, "RADIUS shared secret is not configured")
	}
	secret, err := deps.Secrets(ep.RADIUS.SharedSecret)
	if err != nil || len(secret) == 0 {
		return config.ClientEndpoint{}, nil, domain.NewError(domain.CodeRADIUSSecretMissing, "RADIUS shared secret is not configured")
	}
	return *ep, secret, nil
}

func destFromHandle(ep config.ClientEndpoint, rec radiusruntime.SessionRecord) (string, error) {
	if ep.RADIUS != nil && strings.TrimSpace(ep.RADIUS.CoADestination) != "" {
		return strings.TrimSpace(ep.RADIUS.CoADestination), nil
	}
	if !rec.Peer.IsValid() {
		return "", domain.NewError(domain.CodeInvalidArgument, "session has no peer and endpoint has no coa_destination")
	}
	port := uint16(config.DefaultNASCoAPort)
	if ep.RADIUS != nil && ep.RADIUS.NASCoAPort != 0 {
		port = ep.RADIUS.NASCoAPort
	}
	return net.JoinHostPort(rec.Peer.Addr().String(), strconv.Itoa(int(port))), nil
}

func snapCoATimeout(snap *state.Snapshot) time.Duration {
	if snap == nil || snap.Settings() == nil {
		return config.DefaultCoATimeout
	}
	t := snap.Settings().Listeners.RADIUSAccounting.CoATimeout
	if t <= 0 {
		return config.DefaultCoATimeout
	}
	return t
}

func dynAuthAttrs(code codec.Code, userID, acctSess string, nasIP netip.Addr, nasID string, nasPort uint32, extra []RadiusAttributeValue) (attribute.RawSet, error) {
	out := attribute.RawSet{}
	if userID != "" {
		out = append(out, attribute.Raw{Type: attribute.TypeUserName, Value: []byte(userID)})
	}
	if acctSess != "" {
		out = append(out, attribute.Raw{Type: attribute.TypeAcctSessionID, Value: []byte(acctSess)})
	}
	if nasIP.IsValid() && nasIP.Is4() {
		b := nasIP.As4()
		out = append(out, attribute.Raw{Type: attribute.TypeNASIPAddress, Value: b[:]})
	}
	if nasID != "" {
		out = append(out, attribute.Raw{Type: attribute.TypeNASIdentifier, Value: []byte(nasID)})
	}
	if nasPort != 0 {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], nasPort)
		out = append(out, attribute.Raw{Type: attribute.TypeNASPort, Value: buf[:]})
	}
	pkt := uint8(code)
	for i, a := range extra {
		raw, err := encodeRadiusAttr(a, "attributes["+strconv.Itoa(i)+"]")
		if err != nil {
			return nil, err
		}
		if attribute.Sensitive(raw.Type) {
			return nil, domain.NewError(domain.CodeInvalidArgument, "attributes must not include secret types").
				WithPath("attributes[" + strconv.Itoa(i) + "]")
		}
		if code == codec.CodeDisconnectRequest && isSessionModifyAttr(raw.Type) {
			return nil, domain.NewError(domain.CodeInvalidArgument, "Disconnect-Request may only carry identification attributes").
				WithPath("attributes[" + strconv.Itoa(i) + "]")
		}
		def, ok := attribute.Builtin().LookupIETF(raw.Type)
		if ok && !def.AllowedIn(pkt) {
			return nil, domain.NewError(domain.CodeInvalidArgument, "attribute is not legal on this dynauth packet").
				WithPath("attributes[" + strconv.Itoa(i) + "]")
		}
		out = append(out, raw)
	}
	return out, nil
}

func isSessionModifyAttr(typ uint8) bool {
	switch typ {
	case attribute.TypeSessionTimeout, attribute.TypeIdleTimeout, attribute.TypeReplyMessage:
		return true
	default:
		return false
	}
}

// OmitsExpectedRevision reports operations that reject expected_revision.
func OmitsExpectedRevision(id string) bool {
	return id == IDRadiusCoASend || id == IDRadiusDisconnectSend
}
