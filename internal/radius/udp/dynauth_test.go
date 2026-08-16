package udp

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func TestDynAuthUnknownClientDiscard(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "192.0.2.0/24"))
	idx, err := config.CompileRADIUSIndex(doc.Clients, domain.RoleDynamicAuthorization, domain.CarrierRADIUSUDP)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := idx.Match(net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("127.0.0.1 must miss the compiled dynauth index")
	}

	ln, sessions := startDynAuth(t, doc)
	c := dialUDP(t, ln.Addr().String())
	wire, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    3,
		UserName:      "lab-admin",
		AcctSessionID: "0001",
	}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("unknown client must be silent, got %d bytes", len(got))
	}
	if sessions.Len() != 0 {
		t.Fatal("unknown client must not mutate the index")
	}
}

func TestDynAuthMissingAndInvalidMADiscardNoCacheMutation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	ln, sessions := startDynAuth(t, doc)
	insertSession(t, sessions, "0001")
	c := dialUDP(t, ln.Addr().String())

	var ra [16]byte
	ra[0] = 0x51
	missing, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    9,
		Authenticator: ra,
		AcctSessionID: "0001",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Strip MA by rewriting as header-only Disconnect-Request.
	missing = missing[:20]
	missing[2], missing[3] = 0, 20
	if _, err := c.Write(missing); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("missing MA must be silent, got %d", len(got))
	}

	bad, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    9,
		Authenticator: ra,
		AcctSessionID: "0001",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad[len(bad)-1] ^= 0xff
	if _, err := c.Write(bad); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("invalid MA must be silent, got %d", len(got))
	}

	good, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    9,
		Authenticator: ra,
		AcctSessionID: "0001",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(good); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("valid MA after bad MA must be processed, not treated as a cache hit")
	}
	reply, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("code=%s", reply.Code)
	}
}

func TestDynAuthSessionMissNAK503NeverForwards(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	ln, sessions := startDynAuth(t, doc)
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0x61
	wire, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    4,
		Authenticator: ra,
		UserName:      "lab-admin",
		AcctSessionID: "missing",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("session miss must NAK")
	}
	reply, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectNAK || reply.ErrorCause != 503 {
		t.Fatalf("reply=%+v", reply)
	}
	if sessions.Len() != 0 {
		t.Fatal("miss must not insert")
	}
}

func TestDynAuthDisconnectACKDeletesIndexOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	ln, sessions := startDynAuth(t, doc)
	insertSession(t, sessions, "live-1")
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0x71
	wire, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    5,
		Authenticator: ra,
		AcctSessionID: "live-1",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing ACK")
	}
	reply, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("code=%s", reply.Code)
	}
	if sessions.Len() != 0 {
		t.Fatal("Disconnect-Request must delete the index row")
	}
}

func TestDynAuthCoAStoresLastAttrsAndRejectsUnsupported(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	ln, sessions := startDynAuth(t, doc)
	insertSession(t, sessions, "coa-1")
	c := dialUDP(t, ln.Addr().String())

	var timeout [4]byte
	timeout[3] = 60
	var ra [16]byte
	ra[0] = 0x81
	ok, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.CoARequest,
		Identifier:    6,
		Authenticator: ra,
		AcctSessionID: "coa-1",
		Extra:         []tcodec.Attr{{Type: tcodec.TypeSessionTimeout, Value: timeout[:]}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(ok); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing CoA-ACK")
	}
	ack, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Code != tcodec.CoAACK {
		t.Fatalf("code=%s", ack.Code)
	}
	rec, okLookup := sessions.LookupKey(radiusruntime.SessionKey{EndpointID: "radius-udp", AcctSessionID: "coa-1"})
	if !okLookup || rec.LastCoA.SessionTimeout == nil || *rec.LastCoA.SessionTimeout != 60 {
		t.Fatalf("last CoA=%+v ok=%v", rec.LastCoA, okLookup)
	}

	ra[0] = 0x82
	bad, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.CoARequest,
		Identifier:    7,
		Authenticator: ra,
		AcctSessionID: "coa-1",
		Extra:         []tcodec.Attr{{Type: tcodec.TypeFramedIPAddress, Value: []byte{192, 0, 2, 9}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(bad); err != nil {
		t.Fatal(err)
	}
	nakWire := readUDP(t, c, 2*time.Second)
	if nakWire == nil {
		t.Fatal("missing CoA-NAK")
	}
	nak, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, nakWire)
	if err != nil {
		t.Fatal(err)
	}
	if nak.Code != tcodec.CoANAK || nak.ErrorCause != 401 {
		t.Fatalf("nak=%+v", nak)
	}
}

func TestDynAuthDuplicateIdentifierRaceAndCacheHit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	sessions := newTestSessionIndex(t)
	insertSession(t, sessions, "race-1")
	hold := &holdHandler{started: make(chan struct{}), release: make(chan struct{}), inner: server.DynamicAuth{Sessions: sessions}}
	ln := startDynAuthHandler(t, doc, hold)
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0x91
	req, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    11,
		Authenticator: ra,
		AcctSessionID: "race-1",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hold.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not started")
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 80*time.Millisecond); got != nil {
		t.Fatalf("pending duplicate must be silent, got %d", len(got))
	}
	close(hold.release)
	first := readUDP(t, c, 2*time.Second)
	if first == nil {
		t.Fatal("missing first ACK")
	}
	ack, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, first)
	if err != nil || ack.Code != tcodec.DisconnectACK {
		t.Fatalf("first=%+v err=%v", ack, err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	hit := readUDP(t, c, 2*time.Second)
	if !bytes.Equal(first, hit) {
		t.Fatal("cache hit must replay exact ACK bytes")
	}
}

func TestDynAuthMALastACKNot401(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	ln, sessions := startDynAuth(t, doc)
	insertSession(t, sessions, "ma-last")
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0xb1
	wire, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    13,
		Authenticator: ra,
		AcctSessionID: "ma-last",
		MALast:        true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := tcodec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Attrs[0].Type == tcodec.TypeMessageAuthenticator {
		t.Fatal("fixture must put MA last")
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing reply")
	}
	reply, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("MA last must ACK not 401, got %+v", reply)
	}
}

func TestDynAuthMultipleSessionsNAK508(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	ln, sessions := startDynAuth(t, doc)
	insertSession(t, sessions, "dup-a")
	insertSession(t, sessions, "dup-b")
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0xb2
	wire, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    14,
		Authenticator: ra,
		UserName:      "lab-admin",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing NAK")
	}
	reply, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectNAK || reply.ErrorCause != 508 {
		t.Fatalf("want NAK 508, got %+v", reply)
	}
	if sessions.Len() != 2 {
		t.Fatalf("508 must not delete: %d", sessions.Len())
	}
}

func TestDynAuthToolClientTargetsNASSession(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	nasSec := writeNamedSecret(t, dir, "nas", labSecret)
	toolSec := writeNamedSecret(t, dir, "tool", "ToolRadius-Secret-32-bytes-ok!")
	doc := mustParse(t, dynAuthTwoClientYAML(nasSec, toolSec))
	ln, sessions := startDynAuth(t, doc)
	if !sessions.Apply(radiusruntime.AcctEvent{
		Kind:       radiusruntime.EventStart,
		EndpointID: "nas-udp",
		ClientID:   "nas",
		UserID:     "lab-admin",
		SessionID:  "cross-1",
	}) {
		t.Fatal("insert NAS session")
	}
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0xb3
	wire, err := testclient.EncodeDynAuthRequest([]byte("ToolRadius-Secret-32-bytes-ok!"), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    15,
		Authenticator: ra,
		AcctSessionID: "cross-1",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing ACK")
	}
	reply, err := testclient.DecodeDynAuthReply([]byte("ToolRadius-Secret-32-bytes-ok!"), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("tool client must ACK NAS session, got %+v", reply)
	}
}

func TestDynAuthUserNameNASIPOnUDP(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	ln, sessions := startDynAuth(t, doc)
	nas := netip.MustParseAddr("192.0.2.10")
	if !sessions.Apply(radiusruntime.AcctEvent{
		Kind:       radiusruntime.EventStart,
		EndpointID: "radius-udp",
		ClientID:   "loop",
		UserID:     "lab-admin",
		SessionID:  "named-nas",
		NASIP:      nas,
	}) || !sessions.Apply(radiusruntime.AcctEvent{
		Kind:       radiusruntime.EventStart,
		EndpointID: "radius-udp",
		ClientID:   "loop",
		UserID:     "lab-admin",
		SessionID:  "empty-nas",
	}) {
		t.Fatal("starts")
	}
	c := dialUDP(t, ln.Addr().String())
	b := nas.As4()
	var ra [16]byte
	ra[0] = 0xb4
	wire, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    16,
		Authenticator: ra,
		UserName:      "lab-admin",
		Extra:         []tcodec.Attr{{Type: tcodec.TypeNASIPAddress, Value: b[:]}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing ACK")
	}
	reply, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("named NAS-IP must ACK uniquely, got %+v", reply)
	}
	if _, ok := sessions.LookupKey(radiusruntime.SessionKey{EndpointID: "radius-udp", AcctSessionID: "empty-nas"}); !ok {
		t.Fatal("empty-NAS row must remain")
	}
}

func TestDynAuthInboundDoesNotRequireRadiusDynamicScope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, dynAuthYAML(sec, "127.0.0.0/8"))
	ln, sessions := startDynAuth(t, doc)
	insertSession(t, sessions, "scope-1")
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0xa1
	wire, err := testclient.EncodeDynAuthRequest([]byte(labSecret), testclient.DynAuthRequest{
		Code:          tcodec.DisconnectRequest,
		Identifier:    12,
		Authenticator: ra,
		AcctSessionID: "scope-1",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("packet path must ACK without radius:dynamic")
	}
	reply, err := testclient.DecodeDynAuthReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("code=%s", reply.Code)
	}
}

func dynAuthYAML(secret, cidr string) string {
	return fmt.Sprintf(`
schema_version: 2
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  radius:
    access: {enabled: false}
    accounting: {enabled: false}
    dynamic_authorization:
      enabled: true
      bind: 127.0.0.1:0
      workers: 2
      queue_capacity: 32
      retransmission_ttl: 15s
clients:
  - id: loop
    priority: 10
    match:
      source_cidrs: [%q]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access, accounting, dynamic_authorization]
        radius:
          shared_secret: {file: %q}
          require_message_authenticator: false
`, cidr, secret)
}

func startDynAuth(t *testing.T, doc *config.Document) (*Listener, *radiusruntime.SessionIndex) {
	t.Helper()
	sessions := newTestSessionIndex(t)
	ln := startDynAuthHandler(t, doc, server.DynamicAuth{
		Sessions: sessions,
		Originator: &server.Originator{
			Dial: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
				t.Error("inbound DAS must not originate")
				return nil, nil, fmt.Errorf("forward")
			},
		},
	})
	return ln, sessions
}

func startDynAuthHandler(t *testing.T, doc *config.Document, h server.Handler) *Listener {
	t.Helper()
	ln, _, _ := startRole(t, doc, domain.RoleDynamicAuthorization, h, nil)
	return ln
}

func newTestSessionIndex(t *testing.T) *radiusruntime.SessionIndex {
	t.Helper()
	idx, err := radiusruntime.NewSessionIndex(radiusruntime.Options{
		MaxEntries: 16,
		MaxBytes:   64 << 10,
		TTL:        time.Hour,
		Entropy:    bytes.NewReader(bytes.Repeat([]byte("0123456789abcdef"), 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func writeNamedSecret(t *testing.T, dir, name, value string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func dynAuthTwoClientYAML(nasSecret, toolSecret string) string {
	return fmt.Sprintf(`
schema_version: 2
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  radius:
    access: {enabled: false}
    accounting: {enabled: false}
    dynamic_authorization:
      enabled: true
      bind: 127.0.0.1:0
      workers: 2
      queue_capacity: 32
      retransmission_ttl: 15s
clients:
  - id: nas
    priority: 20
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: nas-udp
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret: {file: %q}
  - id: rfc5176-tool
    priority: 10
    match:
      source_cidrs: ["127.0.0.0/8"]
    endpoints:
      - id: tool-udp
        protocol: radius
        transport: udp
        roles: [dynamic_authorization]
        radius:
          shared_secret: {file: %q}
`, nasSecret, toolSecret)
}

func insertSession(t *testing.T, idx *radiusruntime.SessionIndex, sessionID string) {
	t.Helper()
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind:       radiusruntime.EventStart,
		EndpointID: "radius-udp",
		ClientID:   "loop",
		UserID:     "lab-admin",
		SessionID:  sessionID,
	}) {
		t.Fatal("insert session")
	}
}

func TestDynAuthListenerDefaultOff(t *testing.T) {
	t.Parallel()
	doc := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    access: {enabled: false}
    accounting: {enabled: false}
`)
	if doc.Listeners.RADIUSDynAuth.Enabled {
		t.Fatal("dynamic_authorization must default off")
	}
	if doc.Listeners.RADIUSDynAuth.Bind != "0.0.0.0:3799" {
		t.Fatalf("bind=%q", doc.Listeners.RADIUSDynAuth.Bind)
	}
}
