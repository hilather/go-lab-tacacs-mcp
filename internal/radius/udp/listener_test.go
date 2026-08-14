package udp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const labSecret = "LabRadius-Secret-32-bytes-ok!!"

func TestUnknownClientDiscardUsesCompiledRADIUSIndex(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "192.0.2.0/24", "127.0.0.1:0"))
	idx, err := config.CompileRADIUSIndex(doc.Clients, domain.RoleAccess)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := idx.Match(net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("127.0.0.1 must miss the compiled index")
	}
	if _, _, err := idx.Match(net.ParseIP("192.0.2.10")); err != nil {
		t.Fatal(err)
	}

	ln, _ := startAccess(t, doc, nil)
	c := dialUDP(t, ln.Addr().String())
	req := accessRequest(t, 1, [16]byte{9})
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("unknown client must be silent, got %d bytes", len(got))
	}
}

func TestAccessRejectAndCacheHitPendingPurgeOnUDP(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	hold := &holdHandler{started: make(chan struct{}), release: make(chan struct{}), inner: server.Stub{}}
	doc := mustParse(t, radiusYAML(sec, "127.0.0.0/8", "127.0.0.1:0"))
	ln, _ := startAccess(t, doc, hold)
	c := dialUDP(t, ln.Addr().String())

	var raA [16]byte
	raA[0] = 0x11
	reqA := accessRequest(t, 4, raA)
	if _, err := c.Write(reqA); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hold.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not started")
	}
	if _, err := c.Write(reqA); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 80*time.Millisecond); got != nil {
		t.Fatalf("pending duplicate must be silent, got %d", len(got))
	}
	close(hold.release)
	repA := readUDP(t, c, 2*time.Second)
	if repA == nil {
		t.Fatal("missing first reply")
	}
	assertAccessReject(t, repA, 4, raA, []byte(labSecret))
	_ = readUDP(t, c, 50*time.Millisecond)

	if _, err := c.Write(reqA); err != nil {
		t.Fatal(err)
	}
	repHit := readUDP(t, c, 2*time.Second)
	if !bytes.Equal(repA, repHit) {
		t.Fatal("cache hit must replay exact bytes")
	}

	var raB [16]byte
	raB[0] = 0x22
	reqB := accessRequest(t, 4, raB)
	if _, err := c.Write(reqB); err != nil {
		t.Fatal(err)
	}
	repB := readUDP(t, c, 2*time.Second)
	if repB == nil {
		t.Fatal("missing purged reply")
	}
	if bytes.Equal(repA, repB) {
		t.Fatal("different Request Authenticator must not replay prior bytes")
	}
	assertAccessReject(t, repB, 4, raB, []byte(labSecret))
}

func TestUnknownAccountingClientUsesCompiledRADIUSIndex(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "192.0.2.0/24", "127.0.0.1:0"))
	idx, err := config.CompileRADIUSIndex(doc.Clients, domain.RoleAccounting)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := idx.Match(net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("127.0.0.1 must miss the compiled accounting index")
	}
	ln, _, ring := startAccounting(t, doc)
	c := dialUDP(t, ln.Addr().String())
	req := accountingRequest(t, []byte(labSecret), 8)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("unknown accounting client must be silent, got %d bytes", len(got))
	}
	if ring.Len() != 0 {
		t.Fatal("unknown client must not record")
	}
}

func TestAccountingResponseOnUDP(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "127.0.0.0/8", "127.0.0.1:0"))
	ln, _, ring := startAccounting(t, doc)
	c := dialUDP(t, ln.Addr().String())
	req := accountingRequest(t, []byte(labSecret), 8)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := readUDP(t, c, 2*time.Second)
	if rep == nil {
		t.Fatal("missing accounting response")
	}
	pkt, err := codec.Decode(req)
	if err != nil {
		t.Fatal(err)
	}
	assertSigned(t, rep, codec.CodeAccountingResponse, 8, pkt.Authenticator, []byte(labSecret))
	if ring.Len() != 1 {
		t.Fatalf("recorded=%d", ring.Len())
	}
	got, _ := ring.Latest()
	if got.Type != "start" || got.AcctSessionID != "sess-1" || got.SessionID != 0 {
		t.Fatalf("event=%+v", got)
	}
}

func TestAccountingExactRetryAndDelayTimeAndInterim(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "127.0.0.0/8", "127.0.0.1:0"))
	ln, _, ring := startAccounting(t, doc)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)

	start := accountingAttrs(t, secret, 1, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("same-sess")},
		uint32Raw(attribute.TypeAcctDelayTime, 0),
	})
	if _, err := c.Write(start); err != nil {
		t.Fatal(err)
	}
	rep1 := readUDP(t, c, 2*time.Second)
	if rep1 == nil {
		t.Fatal("missing first start")
	}
	if _, err := c.Write(start); err != nil {
		t.Fatal(err)
	}
	repHit := readUDP(t, c, 2*time.Second)
	if !bytes.Equal(rep1, repHit) {
		t.Fatal("exact retry must replay cached bytes")
	}
	if ring.Len() != 1 {
		t.Fatalf("exact retry recorded extra event: %d", ring.Len())
	}

	delayed := accountingAttrs(t, secret, 2, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("same-sess")},
		uint32Raw(attribute.TypeAcctDelayTime, 7),
	})
	if _, err := c.Write(delayed); err != nil {
		t.Fatal(err)
	}
	repDelay := readUDP(t, c, 2*time.Second)
	if repDelay == nil {
		t.Fatal("missing delay-time response")
	}
	if bytes.Equal(rep1, repDelay) {
		t.Fatal("delay-time retry must be a new Accounting-Response")
	}
	pkt, err := codec.Decode(delayed)
	if err != nil {
		t.Fatal(err)
	}
	assertSigned(t, repDelay, codec.CodeAccountingResponse, 2, pkt.Authenticator, secret)
	if ring.Len() != 1 {
		t.Fatalf("delay-time retry must not record again: %d", ring.Len())
	}

	int1 := accountingAttrs(t, secret, 3, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 3),
		{Type: attribute.TypeAcctSessionID, Value: []byte("same-sess")},
		uint32Raw(attribute.TypeAcctInputOctets, 10),
	})
	int2 := accountingAttrs(t, secret, 4, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 3),
		{Type: attribute.TypeAcctSessionID, Value: []byte("same-sess")},
		uint32Raw(attribute.TypeAcctInputOctets, 20),
	})
	if _, err := c.Write(int1); err != nil {
		t.Fatal(err)
	}
	if readUDP(t, c, 2*time.Second) == nil {
		t.Fatal("missing interim 1")
	}
	if _, err := c.Write(int2); err != nil {
		t.Fatal(err)
	}
	if readUDP(t, c, 2*time.Second) == nil {
		t.Fatal("missing interim 2")
	}
	if ring.Len() != 3 {
		t.Fatalf("start + two interims want 3, got %d", ring.Len())
	}
}

func TestAccountingInboundMAAndInvalidMADiscard(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "127.0.0.0/8", "127.0.0.1:0"))
	ln, _, ring := startAccounting(t, doc)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)

	withMA := accountingRequestWithMA(t, secret, 9, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("ma-ok")},
	})
	if _, err := c.Write(withMA); err != nil {
		t.Fatal(err)
	}
	rep := readUDP(t, c, 2*time.Second)
	if rep == nil {
		t.Fatal("valid inbound MA must not discard")
	}
	pkt, err := codec.Decode(withMA)
	if err != nil {
		t.Fatal(err)
	}
	assertSigned(t, rep, codec.CodeAccountingResponse, 9, pkt.Authenticator, secret)

	bad := append([]byte(nil), withMA...)
	// Flip a byte inside the Message-Authenticator value.
	if len(bad) < 40 {
		t.Fatal("short")
	}
	bad[len(bad)-1] ^= 0xff
	if _, err := c.Write(bad); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("invalid MA must be silent, got %d", len(got))
	}
	if ring.Len() != 1 {
		t.Fatalf("invalid MA recorded extra: %d", ring.Len())
	}
}

func TestInvalidCodeAndShortDatagramDiscard(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "127.0.0.0/8", "127.0.0.1:0"))
	ln, _ := startAccess(t, doc, nil)
	c := dialUDP(t, ln.Addr().String())
	if _, err := c.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	accept := codec.Packet{Code: codec.CodeAccessAccept, Identifier: 1}
	raw, err := codec.Encode(accept)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("malformed/invalid code must be silent, got %d", len(got))
	}
}

type holdHandler struct {
	started chan struct{}
	release chan struct{}
	inner   server.Handler
	once    sync.Once
}

func (h *holdHandler) Handle(ctx context.Context, in server.Request) server.Result {
	h.once.Do(func() { close(h.started) })
	select {
	case <-h.release:
	case <-ctx.Done():
		return server.Result{Action: server.ActionDiscard, Reason: server.ReasonOverload}
	}
	return h.inner.Handle(ctx, in)
}

func startAccess(t *testing.T, doc *config.Document, h server.Handler) (*Listener, *state.Manager) {
	t.Helper()
	ln, mgr, _ := startRole(t, doc, domain.RoleAccess, h)
	return ln, mgr
}

func startAccounting(t *testing.T, doc *config.Document) (*Listener, *state.Manager, *events.Ring) {
	t.Helper()
	ln, mgr, ring := startRole(t, doc, domain.RoleAccounting, nil)
	return ln, mgr, ring
}

func startRole(t *testing.T, doc *config.Document, role domain.ListenerRole, h server.Handler) (*Listener, *state.Manager, *events.Ring) {
	t.Helper()
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	settings := doc.Listeners.RADIUSAccess
	bind := "127.0.0.1:0"
	if role == domain.RoleAccounting {
		settings = doc.Listeners.RADIUSAccounting
	}
	settings.Workers = 2
	settings.QueueCapacity = 32
	settings.WorkerDeadline = 2 * time.Second
	var rec server.RADIUSRecorder
	var ring *events.Ring
	if role == domain.RoleAccounting && h == nil {
		ring = events.New(64, nil)
		t.Cleanup(ring.Close)
		svc, err := aaa.New(aaa.Options{
			Snapshot: mgr.Snapshot,
			Secrets:  lookup,
			Events:   ring,
			Creds:    credentials.Options{Params: credentials.TestParams},
		})
		if err != nil {
			t.Fatal(err)
		}
		rec = svc
	}
	ln, err := Listen(Options{
		Role:     role,
		Bind:     bind,
		Required: true,
		Settings: settings,
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
		Handler:  h,
		Recorder: rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- ln.Serve(ctx) }()
	waitReady(t, ln)
	t.Cleanup(func() {
		cancel()
		_ = ln.Drain(context.Background())
		_ = ln.Close()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
		}
	})
	return ln, mgr, ring
}

func waitReady(t *testing.T, ln *Listener) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ln.Ready() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("listener not ready")
}

func writeSecret(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "radius")
	if err := os.WriteFile(p, []byte(labSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func radiusYAML(secret, cidr, bind string) string {
	return fmt.Sprintf(`
schema_version: 2
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  radius:
    access:
      enabled: true
      bind: %s
      workers: 2
      queue_capacity: 32
      retransmission_ttl: 15s
    accounting:
      enabled: true
      bind: 127.0.0.2:0
      workers: 2
clients:
  - id: loop
    priority: 10
    match:
      source_cidrs: [%q]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret: {file: %q}
          require_message_authenticator: true
`, bind, cidr, secret)
}

func mustParse(t *testing.T, src string) *config.Document {
	t.Helper()
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func dialUDP(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readUDP(t *testing.T, c *net.UDPConn, wait time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

func accessRequest(t *testing.T, id uint8, ra [16]byte) []byte {
	t.Helper()
	return signAccessRequest(t, []byte(labSecret), codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    id,
		Authenticator: ra,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("alice")},
		},
	})
}

func signAccessRequest(t *testing.T, secret []byte, pkt codec.Packet) []byte {
	t.Helper()
	attrs := append(attribute.RawSet(nil), pkt.Attributes...)
	attrs = append(attrs, attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)})
	pkt.Attributes = attrs
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := crypto.MessageAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	off := codec.HeaderSize
	for off+2 <= len(raw) {
		alen := int(raw[off+1])
		if raw[off] == attribute.TypeMessageAuthenticator {
			copy(raw[off+2:off+18], mac[:])
			return raw
		}
		off += alen
	}
	t.Fatal("Message-Authenticator missing after encode")
	return raw
}

func accountingRequest(t *testing.T, secret []byte, id uint8) []byte {
	t.Helper()
	return accountingAttrs(t, secret, id, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("sess-1")},
	})
}

func accountingAttrs(t *testing.T, secret []byte, id uint8, attrs attribute.RawSet) []byte {
	t.Helper()
	pkt := codec.Packet{Code: codec.CodeAccountingRequest, Identifier: id, Attributes: attrs}
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := crypto.AccountingRequestAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Authenticator = auth
	out, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func uint32Raw(typ uint8, v uint32) attribute.Raw {
	return attribute.Raw{Type: typ, Value: []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}}
}

func accountingRequestWithMA(t *testing.T, secret []byte, id uint8, attrs attribute.RawSet) []byte {
	t.Helper()
	withMA := attrs.Clone()
	withMA = append(withMA, attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)})
	pkt := codec.Packet{Code: codec.CodeAccountingRequest, Identifier: id, Attributes: withMA}
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := crypto.AccountingRequestAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Authenticator = auth
	raw, err = codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := crypto.MessageAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Attributes[len(pkt.Attributes)-1].Value = append([]byte(nil), mac[:]...)
	out, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertAccessReject(t *testing.T, wire []byte, id uint8, ra [16]byte, secret []byte) {
	t.Helper()
	assertSigned(t, wire, codec.CodeAccessReject, id, ra, secret)
}

func assertSigned(t *testing.T, wire []byte, code codec.Code, id uint8, reqAuth [16]byte, secret []byte) {
	t.Helper()
	if err := crypto.ValidateResponseAuthenticator(secret, wire, reqAuth); err != nil {
		t.Fatalf("response authenticator: %v", err)
	}
	work := append([]byte(nil), wire...)
	copy(work[4:20], reqAuth[:])
	if err := crypto.ValidateMessageAuthenticator(secret, work); err != nil {
		t.Fatalf("message authenticator: %v", err)
	}
	pkt, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Code != code || pkt.Identifier != id {
		t.Fatalf("code=%s id=%d", pkt.Code, pkt.Identifier)
	}
	if pkt.Attributes.Len() == 0 || pkt.Attributes[0].Type != attribute.TypeMessageAuthenticator {
		t.Fatal("Message-Authenticator must be first")
	}
}
