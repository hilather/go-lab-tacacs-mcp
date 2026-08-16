package operations

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
)

func TestRadiusSessionsListRedactsAcctSessionID(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind:       radiusruntime.EventStart,
		EndpointID: "acct-udp",
		ClientID:   "lab-switches",
		UserID:     "lab-admin",
		SessionID:  "secret-acct-session-zz9",
		Peer:       netip.MustParseAddrPort("192.0.2.10:1813"),
	}) {
		t.Fatal("insert")
	}
	reg, _ := radiusTestRegistry(t)
	// Rebuild registry with the index.
	m := mustRadiusMgr(t)
	reg, err := New(mustSpec(t), Deps{State: m, RADIUSSessions: idx})
	if err != nil {
		t.Fatal(err)
	}
	reader := Actor{ID: "r", Scopes: []string{"state:read"}}
	res, err := reg.Invoke(context.Background(), IDRadiusSessionsList, m.Snapshot(), Input{Actor: reader, Request: ListRadiusSessionsRequest{}})
	if err != nil {
		t.Fatal(err)
	}
	page := res.Data.(RadiusSessionList)
	if len(page.Items) != 1 || page.Items[0].SessionHandle == "" {
		t.Fatalf("page=%+v", page)
	}
	if page.Items[0].AcctSessionID != "" {
		t.Fatal("acct_session_id leaked without events:sensitive")
	}
	if strings.Contains(page.Items[0].SessionHandle, "secret-acct-session-zz9") {
		t.Fatal("handle must not be the raw session id")
	}
	sens := Actor{ID: "s", Scopes: []string{"state:read", "events:sensitive"}}
	res, err = reg.Invoke(context.Background(), IDRadiusSessionsList, m.Snapshot(), Input{Actor: sens, Request: ListRadiusSessionsRequest{}})
	if err != nil {
		t.Fatal(err)
	}
	got := res.Data.(RadiusSessionList)
	if got.Items[0].AcctSessionID != "secret-acct-session-zz9" {
		t.Fatalf("sensitive=%+v", got.Items[0])
	}
}

func TestRadiusSessionsListRequiresReadScope(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	_, err := reg.Invoke(context.Background(), IDRadiusSessionsList, m.Snapshot(), Input{
		Actor: Actor{ID: "t", Scopes: []string{"radius:dynamic"}},
	})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("err=%v", err)
	}
}

func TestRadiusDynAuthRequiresScope(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	req := RadiusDynamicAuthRequest{ClientID: "lab-switches", Destination: "192.0.2.10:3799"}
	for _, id := range []string{IDRadiusDisconnectSend, IDRadiusCoASend} {
		_, err := reg.Invoke(context.Background(), id, m.Snapshot(), Input{
			Actor:   Actor{ID: "t", Scopes: []string{"state:write", "state:read", "policy:test"}},
			Request: req,
		})
		if !isCode(err, domain.CodePermissionDenied) {
			t.Fatalf("%s err=%v", id, err)
		}
	}
}

func TestRadiusDynAuthRejectsExpectedRevision(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	rev := m.Revision()
	_, err := reg.Invoke(context.Background(), IDRadiusDisconnectSend, m.Snapshot(), Input{
		Actor:            Actor{ID: "t", Scopes: []string{"radius:dynamic"}},
		ExpectedRevision: &rev,
		Request:          RadiusDynamicAuthRequest{ClientID: "lab-switches", Destination: "192.0.2.10:3799"},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}

func TestRadiusDynAuthRejectsBothShapes(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	_, err := reg.Invoke(context.Background(), IDRadiusCoASend, m.Snapshot(), Input{
		Actor: Actor{ID: "t", Scopes: []string{"radius:dynamic"}},
		Request: RadiusDynamicAuthRequest{
			SessionHandle: "01J",
			ClientID:      "lab-switches",
			Destination:   "192.0.2.10:3799",
		},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}

func TestRadiusDynAuthUnknownClient(t *testing.T) {
	t.Parallel()
	m := mustRadiusMgr(t)
	reg, err := New(mustSpec(t), Deps{State: m, Secrets: radiusLookup, Originator: &server.Originator{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Invoke(context.Background(), IDRadiusDisconnectSend, m.Snapshot(), Input{
		Actor:   Actor{ID: "t", Scopes: []string{"radius:dynamic"}},
		Request: RadiusDynamicAuthRequest{ClientID: "nosuch", Destination: "192.0.2.10:3799"},
	})
	if !isCode(err, domain.CodeNotFound) {
		t.Fatalf("err=%v", err)
	}
	_ = reg
}

func TestOriginateCacheKeyDistinguishesCodeAndAttrs(t *testing.T) {
	t.Parallel()
	id := "h:01HANDLE"
	dest := "192.0.2.10:3799"
	user := attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("lab-admin")}}
	coa := originateCacheKey(id, dest, codec.CodeCoARequest, user)
	disc := originateCacheKey(id, dest, codec.CodeDisconnectRequest, user)
	if coa == disc || coa == "" {
		t.Fatalf("code must change key: coa=%s disc=%s", coa, disc)
	}
	var timeout [4]byte
	binary.BigEndian.PutUint32(timeout[:], 60)
	coaTO := originateCacheKey(id, dest, codec.CodeCoARequest, append(user, attribute.Raw{Type: attribute.TypeSessionTimeout, Value: timeout[:]}))
	if coaTO == coa {
		t.Fatal("extra attrs must change key")
	}
	again := originateCacheKey(id, dest, codec.CodeCoARequest, user)
	if again != coa {
		t.Fatal("same inputs must be stable")
	}
}

func TestRadiusDynAuthHandleMiss(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	m := mustRadiusMgr(t)
	reg, err := New(mustSpec(t), Deps{State: m, RADIUSSessions: idx, Originator: &server.Originator{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Invoke(context.Background(), IDRadiusDisconnectSend, m.Snapshot(), Input{
		Actor:   Actor{ID: "t", Scopes: []string{"radius:dynamic"}},
		Request: RadiusDynamicAuthRequest{SessionHandle: "01NOTFOUNDHANDLE0000000000"},
	})
	if !isCode(err, domain.CodeNotFound) {
		t.Fatalf("err=%v", err)
	}
}

func TestRadiusDynAuthCoAThenDisconnectUsesDistinctDatagrams(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind:       radiusruntime.EventStart,
		EndpointID: "acct-udp",
		ClientID:   "lab-switches",
		UserID:     "lab-admin",
		SessionID:  "sess-coa-disc",
		Peer:       netip.MustParseAddrPort("192.0.2.10:1813"),
	}) {
		t.Fatal("insert")
	}
	rec, ok := idx.LookupKey(radiusruntime.SessionKey{EndpointID: "acct-udp", AcctSessionID: "sess-coa-disc"})
	if !ok {
		t.Fatal("missing")
	}
	var mu sync.Mutex
	var codes []byte
	org := &server.Originator{
		Dial: func(_ context.Context, _, address string) (net.PacketConn, *net.UDPAddr, error) {
			addr, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, nil, err
			}
			return timeoutRecordConn(func(p []byte) {
				if len(p) > 0 {
					mu.Lock()
					codes = append(codes, p[0])
					mu.Unlock()
				}
			}), addr, nil
		},
	}
	m := mustRadiusMgr(t)
	reg, err := New(mustSpec(t), Deps{State: m, RADIUSSessions: idx, Secrets: radiusLookup, Originator: org})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{ID: "t", Scopes: []string{"radius:dynamic"}}
	req := RadiusDynamicAuthRequest{SessionHandle: rec.Handle}
	if _, err := reg.Invoke(context.Background(), IDRadiusCoASend, m.Snapshot(), Input{Actor: actor, Request: req}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Invoke(context.Background(), IDRadiusDisconnectSend, m.Snapshot(), Input{Actor: actor, Request: req}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(codes) != 2 || codes[0] != byte(codec.CodeCoARequest) || codes[1] != byte(codec.CodeDisconnectRequest) {
		t.Fatalf("codes=%v", codes)
	}
}

func timeoutRecordConn(onWrite func([]byte)) net.PacketConn {
	return &captureConn{onWrite: onWrite}
}

type captureConn struct {
	onWrite func([]byte)
}

func (c *captureConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, timeoutNetErr{}
}
func (c *captureConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.onWrite != nil {
		c.onWrite(p)
	}
	return len(p), nil
}
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

func TestRadiusDynAuthHandleDoesNotUseEndpointIDAsSecret(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	// Record looks like a TLS accounting endpoint id; secret must still come from UDP.
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind:       radiusruntime.EventStart,
		EndpointID: "radius-tls-not-a-secret",
		ClientID:   "lab-switches",
		UserID:     "lab-admin",
		SessionID:  "sess-1",
		Peer:       netip.MustParseAddrPort("192.0.2.10:1813"),
	}) {
		t.Fatal("insert")
	}
	rec, ok := idx.LookupKey(radiusruntime.SessionKey{EndpointID: "radius-tls-not-a-secret", AcctSessionID: "sess-1"})
	if !ok {
		t.Fatal("missing")
	}
	m := mustRadiusMgr(t)
	reg, err := New(mustSpec(t), Deps{State: m, RADIUSSessions: idx, Secrets: radiusLookup, Originator: &server.Originator{}})
	if err != nil {
		t.Fatal(err)
	}
	// Originator with default dial to an unused dest will timeout, not RADIUS_SECRET_MISSING.
	res, err := reg.Invoke(context.Background(), IDRadiusDisconnectSend, m.Snapshot(), Input{
		Actor:   Actor{ID: "t", Scopes: []string{"radius:dynamic"}},
		Request: RadiusDynamicAuthRequest{SessionHandle: rec.Handle},
	})
	if err != nil {
		// Missing dest/secret would be RADIUS_SECRET_MISSING or invalid_argument.
		if isCode(err, domain.CodeRADIUSSecretMissing) {
			t.Fatalf("must not treat EndpointID as secret key: %v", err)
		}
		t.Fatal(err)
	}
	out := res.Data.(RadiusDynamicAuthResult)
	if out.Outcome != "timeout" && out.Outcome != "ack" && out.Outcome != "nak" {
		t.Fatalf("outcome=%+v", out)
	}
}

func mustSessionIndex(t *testing.T) *radiusruntime.SessionIndex {
	t.Helper()
	idx, err := radiusruntime.NewSessionIndex(radiusruntime.Options{
		MaxEntries: 32,
		MaxBytes:   64 << 10,
		TTL:        time.Hour,
		Entropy:    strings.NewReader(strings.Repeat("0123456789abcdef", 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return idx
}
