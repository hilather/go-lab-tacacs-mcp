package udp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/eap/peap"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestIndependentTestclientEAPIdentityMD5Wire(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessEAP(t, false)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)
	chalSecret := []byte(accessTestChallenge)

	var ra [16]byte
	ra[0] = 0xb1
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    21,
		Authenticator: ra,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			testclient.EAPMessageAttr(testclient.EAPIdentityResponse(1, "lab-admin")),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing Challenge")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatalf("independent client rejected Challenge: %v", err)
	}
	if reply.Code != tcodec.AccessChallenge {
		t.Fatalf("code=%s", reply.Code)
	}
	stateVal, ok := testclient.FirstState(reply.Attrs)
	if !ok {
		t.Fatal("missing State")
	}
	eap, err := testclient.FirstEAP(reply.Attrs)
	if err != nil || eap.Code != testclient.EAPCodeRequest || eap.Type != testclient.EAPTypeMD5 {
		t.Fatalf("eap=%+v err=%v", eap, err)
	}
	md5chal, err := testclient.ParseMD5Challenge(eap)
	if err != nil {
		t.Fatal(err)
	}
	hash := testclient.MD5Response(eap.Identifier, chalSecret, md5chal)

	var ra2 [16]byte
	ra2[0] = 0xb2
	cont, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    22,
		Authenticator: ra2,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			{Type: tcodec.TypeState, Value: stateVal},
			testclient.EAPMessageAttr(testclient.EAPMD5Response(eap.Identifier, hash)),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(cont); err != nil {
		t.Fatal(err)
	}
	acc := readUDP(t, c, 2*time.Second)
	if acc == nil {
		t.Fatal("missing Accept")
	}
	accept, err := testclient.DecodeAccessReply(secret, ra2, acc)
	if err != nil {
		t.Fatalf("independent client rejected Accept: %v", err)
	}
	if accept.Code != tcodec.AccessAccept {
		t.Fatalf("code=%s", accept.Code)
	}
	okEAP, err := testclient.FirstEAP(accept.Attrs)
	if err != nil || okEAP.Code != testclient.EAPCodeSuccess {
		t.Fatalf("eap=%+v err=%v", okEAP, err)
	}
}

func TestIndependentTestclientPEAPStartWire(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessPEAP(t)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0xb6
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    26,
		Authenticator: ra,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			testclient.EAPMessageAttr(testclient.EAPIdentityResponse(1, "lab-admin")),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing Challenge")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatalf("independent client rejected Challenge: %v", err)
	}
	if reply.Code != tcodec.AccessChallenge {
		t.Fatalf("code=%s", reply.Code)
	}
	if _, ok := testclient.FirstState(reply.Attrs); !ok {
		t.Fatal("missing State")
	}
	eap, err := testclient.FirstEAP(reply.Attrs)
	if err != nil || eap.Code != testclient.EAPCodeRequest || eap.Type != testclient.EAPTypePEAP {
		t.Fatalf("eap=%+v err=%v", eap, err)
	}
	if len(eap.Data) < 1 || eap.Data[0] != 0x20 {
		t.Fatalf("want PEAPv0 Start flag, data=%x", eap.Data)
	}
}

func TestIndependentTestclientPEAPHandshakeAndAccept(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessPEAP(t)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)
	peer := newUDPPEAPPeer(t)
	state, eapID := udpPEAPStart(t, c, secret)
	reply := udpPEAPPump(t, c, secret, peer, state, eapID)
	if reply.Code != tcodec.AccessChallenge {
		t.Fatalf("after hs code=%s", reply.Code)
	}
	inner, err := peer.ReadApp(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, err := peap.DecodeInner(inner)
	if err != nil || req.Type != peap.InnerIdentity {
		t.Fatalf("inner ident %+v err=%v", req, err)
	}
	if err := peer.WriteApp(peap.EncodeInner(peap.InnerPacket{
		Code: 2, Identifier: req.Identifier, Type: peap.InnerIdentity, HasType: true, Data: []byte("lab-admin"),
	})); err != nil {
		t.Fatal(err)
	}
	state, eapID = mustStateEAP(t, reply)
	reply = udpSendPEAP(t, c, secret, state, eapID, peer.Take())
	if reply.Code != tcodec.AccessChallenge {
		t.Fatalf("after ident code=%s", reply.Code)
	}
	udpFeed(t, peer, reply)
	chalRaw, err := peer.ReadApp(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	chalPkt, err := peap.DecodeInner(chalRaw)
	if err != nil || chalPkt.Type != peap.InnerMSCHAPv2 || len(chalPkt.Data) < 21 {
		t.Fatalf("mschap %+v err=%v", chalPkt, err)
	}
	authChal := chalPkt.Data[5:21]
	peerChal := bytes.Repeat([]byte{0x42}, 16)
	resp := credentials.MSCHAPv2Response([]byte(accessTestChallenge), []byte("lab-admin"), authChal, peerChal)
	data := append([]byte{peap.MSCHAPOpResponse, chalPkt.Data[1], 0, 54, 49}, resp...)
	data = append(data, []byte("lab-admin")...)
	if err := peer.WriteApp(peap.EncodeInner(peap.InnerPacket{
		Code: 2, Identifier: chalPkt.Identifier, Type: peap.InnerMSCHAPv2, HasType: true, Data: data,
	})); err != nil {
		t.Fatal(err)
	}
	state, eapID = mustStateEAP(t, reply)
	reply = udpSendPEAP(t, c, secret, state, eapID, peer.Take())
	if reply.Code != tcodec.AccessChallenge {
		t.Fatalf("after mschap code=%s", reply.Code)
	}
	state, eapID = mustStateEAP(t, reply)
	reply = udpSendPEAP(t, c, secret, state, eapID, nil)
	if reply.Code != tcodec.AccessAccept {
		t.Fatalf("accept code=%s", reply.Code)
	}
	okEAP, err := testclient.FirstEAP(reply.Attrs)
	if err != nil || okEAP.Code != testclient.EAPCodeSuccess {
		t.Fatalf("outer eap=%+v err=%v", okEAP, err)
	}
}

func TestIndependentTestclientUnsupportedEAPNoChallenge(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessEAP(t, false)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0xb3
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    23,
		Authenticator: ra,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			testclient.EAPMessageAttr(testclient.EAPTypeResponse(1, 25, []byte{0x00})), // PEAP
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing Reject")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.AccessReject {
		t.Fatalf("code=%s", reply.Code)
	}
	if _, ok := testclient.FirstState(reply.Attrs); ok {
		t.Fatal("must not leak State")
	}
	eap, err := testclient.FirstEAP(reply.Attrs)
	if err != nil || eap.Code != testclient.EAPCodeFailure || eap.HasType {
		t.Fatalf("generic failure=%+v err=%v", eap, err)
	}
}

func TestIndependentTestclientEAPMustChangeIndistinguishable(t *testing.T) {
	t.Parallel()
	ln, mgr := startAccessEAP(t, false)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)

	badEAP := eapConversationFailure(t, c, secret, []byte("wrong-secret!!!!!"))

	rev := mgr.Revision()
	flag := true
	if _, err := mgr.UpdateUser("lab-admin", state.UpdateUser{MustChangeLogin: &flag}, &rev); err != nil {
		t.Fatal(err)
	}
	mustEAP := eapConversationFailure(t, c, secret, []byte(accessTestChallenge))

	if badEAP.Code != testclient.EAPCodeFailure || mustEAP.Code != testclient.EAPCodeFailure {
		t.Fatalf("codes %d %d", badEAP.Code, mustEAP.Code)
	}
	if badEAP.HasType || mustEAP.HasType || len(badEAP.Data) != 0 || len(mustEAP.Data) != 0 {
		t.Fatalf("distinguishable payload bad=%+v must=%+v", badEAP, mustEAP)
	}
}

func TestIndependentTestclientEAPDefaultMethodsReject(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessPolicy(t)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0xb4
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    24,
		Authenticator: ra,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			testclient.EAPMessageAttr(testclient.EAPIdentityResponse(1, "lab-admin")),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing Reject")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.AccessReject {
		t.Fatalf("code=%s", reply.Code)
	}
	if reply.Code == tcodec.AccessChallenge {
		t.Fatal("default [pap,chap] must not Challenge")
	}
	if _, ok := testclient.FirstState(reply.Attrs); ok {
		t.Fatal("must not emit State")
	}
}

func TestIndependentTestclientForgedState(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessEAP(t, false)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0xb5
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    25,
		Authenticator: ra,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			{Type: tcodec.TypeState, Value: []byte("forged-client-state")},
			testclient.EAPMessageAttr(testclient.EAPMD5Response(1, make([]byte, 16))),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing Reject")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.AccessReject {
		t.Fatalf("code=%s", reply.Code)
	}
	if reply.Code == tcodec.AccessChallenge {
		t.Fatal("forged State must not Challenge")
	}
}

func eapConversationFailure(t *testing.T, c *net.UDPConn, secret, chalSecret []byte) testclient.EAPPacket {
	t.Helper()
	var ra [16]byte
	if _, err := rand.Read(ra[:]); err != nil {
		t.Fatal(err)
	}
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    31,
		Authenticator: ra,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			testclient.EAPMessageAttr(testclient.EAPIdentityResponse(1, "lab-admin")),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing Challenge")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.AccessChallenge {
		t.Fatalf("code=%s", reply.Code)
	}
	stateVal, ok := testclient.FirstState(reply.Attrs)
	if !ok {
		t.Fatal("missing State")
	}
	eap, err := testclient.FirstEAP(reply.Attrs)
	if err != nil {
		t.Fatal(err)
	}
	md5chal, err := testclient.ParseMD5Challenge(eap)
	if err != nil {
		t.Fatal(err)
	}
	hash := testclient.MD5Response(eap.Identifier, chalSecret, md5chal)
	var ra2 [16]byte
	if _, err := rand.Read(ra2[:]); err != nil {
		t.Fatal(err)
	}
	cont, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    32,
		Authenticator: ra2,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			{Type: tcodec.TypeState, Value: stateVal},
			testclient.EAPMessageAttr(testclient.EAPMD5Response(eap.Identifier, hash)),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(cont); err != nil {
		t.Fatal(err)
	}
	rej := readUDP(t, c, 2*time.Second)
	if rej == nil {
		t.Fatal("missing Reject")
	}
	decoded, err := testclient.DecodeAccessReply(secret, ra2, rej)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Code != tcodec.AccessReject {
		t.Fatalf("code=%s", decoded.Code)
	}
	if _, ok := testclient.FirstState(decoded.Attrs); ok {
		t.Fatal("Reject must not carry State")
	}
	out, err := testclient.FirstEAP(decoded.Attrs)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func startAccessPEAP(t *testing.T) (*Listener, *state.Manager) {
	t.Helper()
	return startAccessEAPWithMethods(t, "[peap]", false)
}

func startAccessEAP(t *testing.T, mustChange bool) (*Listener, *state.Manager) {
	t.Helper()
	return startAccessEAPWithMethods(t, "[pap, chap, eap]", mustChange)
}

func startAccessEAPWithMethods(t *testing.T, methods string, mustChange bool) (*Listener, *state.Manager) {
	t.Helper()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	login := filepath.Join(dir, "login")
	chal := filepath.Join(dir, "chal")
	phc, err := credentials.DeriveArgon2id([]byte(accessTestPassword), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(login, phc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chal, []byte(accessTestChallenge), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := mustParse(t, radiusEAPYAML(sec, login, chal, methods, mustChange))
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := aaa.New(aaa.Options{
		Manager: mgr,
		Secrets: lookup,
		Events:  events.New(8, domain.SystemClock{}),
		Creds:   credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := runtime.NewChallengeStore(64, 64<<10, 30*time.Second, time.Now)
	settings := doc.Listeners.RADIUSAccess
	settings.Workers = 2
	settings.QueueCapacity = 32
	settings.WorkerDeadline = 2 * time.Second
	access := server.Access{AAA: svc, Store: store, Entropy: rand.Reader}
	if strings.Contains(methods, "peap") {
		srv, err := peap.NewServer(mustUDPPEAPCert(t))
		if err != nil {
			t.Fatal(err)
		}
		access.PEAP = srv
		access.Tunnels = peap.NewRegistry()
	}
	ln, err := Listen(Options{
		Role:       domain.RoleAccess,
		Bind:       "127.0.0.1:0",
		Required:   true,
		Settings:   settings,
		Snapshot:   mgr.Snapshot,
		Secrets:    lookup,
		Handler:    access,
		Challenges: store,
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
	return ln, mgr
}

func radiusEAPYAML(secret, login, chal, methods string, mustChange bool) string {
	return `
schema_version: 2
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  radius:
    access:
      enabled: true
      bind: 127.0.0.1:0
      workers: 2
      queue_capacity: 32
      retransmission_ttl: 15s
    accounting:
      enabled: false
clients:
  - id: loop
    priority: 10
    match:
      source_cidrs: ["127.0.0.0/8"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: ` + secret + `}
          allowed_authentication_methods: ` + methods + `
          access_policy_id: default-radius-access
groups:
  - id: lab-admins
    priority: 10
users:
  - id: lab-admin
    group_ids: [lab-admins]
    must_change_login: ` + boolYAML(mustChange) + `
    credentials:
      login:
        verifier: {file: ` + login + `}
      challenge:
        secret: {file: ` + chal + `}
radius_reply_profiles:
  - id: lab-accept
    attributes:
      - name: Session-Timeout
        value: "600"
radius_policies:
  - id: default-radius-access
    rules:
      - id: permit-lab-admins
        match:
          groups_any: [lab-admins]
        effect: permit
        reply_profiles: [lab-accept]
`
}

func mustUDPPEAPCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "peap.lab.example"},
		DNSNames:              []string{"peap.lab.example"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func udpPEAPStart(t *testing.T, c *net.UDPConn, secret []byte) ([]byte, byte) {
	t.Helper()
	var ra [16]byte
	ra[0] = 0xc1
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier: 41, Authenticator: ra, UserName: "lab-admin", IncludeMA: true,
		Extra: []tcodec.Attr{testclient.EAPMessageAttr(testclient.EAPIdentityResponse(1, "lab-admin"))},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil || reply.Code != tcodec.AccessChallenge {
		t.Fatalf("start %+v err=%v", reply, err)
	}
	return mustStateEAP(t, reply)
}

func udpPEAPPump(t *testing.T, c *net.UDPConn, secret []byte, peer *udpPEAPPeer, state []byte, eapID byte) testclient.AccessReply {
	t.Helper()
	hello := peer.Wait(2 * time.Second)
	var reply testclient.AccessReply
	for _, part := range peap.EncodeFlight(hello) {
		reply = udpSendPEAPBody(t, c, secret, state, eapID, part)
		if reply.Code != tcodec.AccessChallenge {
			t.Fatalf("hello code=%s", reply.Code)
		}
		state, eapID = mustStateEAP(t, reply)
		state, eapID, reply = udpDrain(t, c, secret, peer, state, eapID, reply)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !peer.Done() {
		more := peer.Take()
		if len(more) == 0 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		for _, part := range peap.EncodeFlight(more) {
			reply = udpSendPEAPBody(t, c, secret, state, eapID, part)
			if reply.Code != tcodec.AccessChallenge {
				t.Fatalf("hs code=%s", reply.Code)
			}
			state, eapID = mustStateEAP(t, reply)
			state, eapID, reply = udpDrain(t, c, secret, peer, state, eapID, reply)
		}
	}
	if !peer.Done() {
		t.Fatal("peer handshake incomplete")
	}
	if more := peer.Take(); len(more) > 0 {
		for _, part := range peap.EncodeFlight(more) {
			reply = udpSendPEAPBody(t, c, secret, state, eapID, part)
			if reply.Code != tcodec.AccessChallenge {
				t.Fatalf("finished code=%s", reply.Code)
			}
			state, eapID = mustStateEAP(t, reply)
			state, eapID, reply = udpDrain(t, c, secret, peer, state, eapID, reply)
		}
	}
	return reply
}

func udpSendPEAP(t *testing.T, c *net.UDPConn, secret, state []byte, eapID byte, tlsData []byte) testclient.AccessReply {
	t.Helper()
	return udpSendPEAPBody(t, c, secret, state, eapID, peap.Encode(peap.Payload{Version: peap.Version0, TLSData: tlsData}))
}

func udpSendPEAPBody(t *testing.T, c *net.UDPConn, secret, state []byte, eapID byte, body []byte) testclient.AccessReply {
	t.Helper()
	var ra [16]byte
	if _, err := rand.Read(ra[:]); err != nil {
		t.Fatal(err)
	}
	pkt := testclient.EncodeEAP(testclient.EAPPacket{Code: testclient.EAPCodeResponse, Identifier: eapID, Type: testclient.EAPTypePEAP, HasType: true, Data: body})
	extra := []tcodec.Attr{{Type: tcodec.TypeState, Value: state}}
	for len(pkt) > 0 {
		n := len(pkt)
		if n > 253 {
			n = 253
		}
		extra = append(extra, tcodec.Attr{Type: tcodec.TypeEAPMessage, Value: pkt[:n]})
		pkt = pkt[n:]
	}
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier: 42, Authenticator: ra, UserName: "lab-admin", IncludeMA: true, Extra: extra,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing RADIUS reply")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func udpDrain(t *testing.T, c *net.UDPConn, secret []byte, peer *udpPEAPPeer, state []byte, eapID byte, reply testclient.AccessReply) ([]byte, byte, testclient.AccessReply) {
	t.Helper()
	for i := 0; i < 8; i++ {
		eap, err := testclient.FirstEAP(reply.Attrs)
		if err != nil {
			t.Fatal(err)
		}
		body, err := peap.Parse(eap.Data)
		if err != nil {
			t.Fatal(err)
		}
		if len(body.TLSData) > 0 {
			peer.Push(body.TLSData)
		}
		if !body.MoreFragments {
			return state, eapID, reply
		}
		reply = udpSendPEAP(t, c, secret, state, eapID, nil)
		if reply.Code != tcodec.AccessChallenge {
			t.Fatalf("ack code=%s", reply.Code)
		}
		state, eapID = mustStateEAP(t, reply)
	}
	t.Fatal("too many fragments")
	return state, eapID, reply
}

func udpFeed(t *testing.T, peer *udpPEAPPeer, reply testclient.AccessReply) {
	t.Helper()
	eap, err := testclient.FirstEAP(reply.Attrs)
	if err != nil {
		t.Fatal(err)
	}
	body, err := peap.Parse(eap.Data)
	if err != nil {
		t.Fatal(err)
	}
	peer.Push(body.TLSData)
}

func mustStateEAP(t *testing.T, reply testclient.AccessReply) ([]byte, byte) {
	t.Helper()
	st, ok := testclient.FirstState(reply.Attrs)
	if !ok {
		t.Fatal("missing State")
	}
	eap, err := testclient.FirstEAP(reply.Attrs)
	if err != nil {
		t.Fatal(err)
	}
	return st, eap.Identifier
}

type udpPEAPPeer struct {
	conn     *tls.Conn
	toPeer   *udpPipe
	fromPeer *udpPipe
	hs       chan error
	done     bool
	hsErr    error
}

func newUDPPEAPPeer(t *testing.T) *udpPEAPPeer {
	t.Helper()
	toPeer, fromPeer := newUDPPipe(), newUDPPipe()
	conn := tls.Client(&udpDuplex{r: toPeer, w: fromPeer}, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: "peap.lab.example", InsecureSkipVerify: true, SessionTicketsDisabled: true,
	})
	hs := make(chan error, 1)
	go func() { hs <- conn.Handshake() }()
	return &udpPEAPPeer{conn: conn, toPeer: toPeer, fromPeer: fromPeer, hs: hs}
}

func (p *udpPEAPPeer) Wait(d time.Duration) []byte {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if rec := p.fromPeer.take(); len(rec) > 0 {
			return rec
		}
		time.Sleep(2 * time.Millisecond)
	}
	panic("no peer hello")
}

func (p *udpPEAPPeer) Take() []byte { return p.fromPeer.take() }
func (p *udpPEAPPeer) Push(b []byte) {
	if len(b) > 0 {
		_, _ = p.toPeer.Write(b)
	}
}

func (p *udpPEAPPeer) Done() bool {
	if p.done {
		return p.hsErr == nil
	}
	select {
	case err := <-p.hs:
		p.done = true
		p.hsErr = err
		return err == nil
	default:
		return false
	}
}

func (p *udpPEAPPeer) ReadApp(d time.Duration) ([]byte, error) {
	_ = p.conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 2048)
	n, err := p.conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

func (p *udpPEAPPeer) WriteApp(b []byte) error {
	_, err := p.conn.Write(b)
	return err
}

type udpPipe struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  []byte
}

func newUDPPipe() *udpPipe {
	p := &udpPipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *udpPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = append(p.buf, b...)
	p.cond.Broadcast()
	return len(b), nil
}

func (p *udpPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 {
		p.cond.Wait()
	}
	n := copy(b, p.buf)
	p.buf = append([]byte(nil), p.buf[n:]...)
	return n, nil
}

func (p *udpPipe) take() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.buf
	p.buf = nil
	return out
}

func (p *udpPipe) Close() error { return nil }

type udpDuplex struct{ r, w *udpPipe }

func (d *udpDuplex) Read(b []byte) (int, error)  { return d.r.Read(b) }
func (d *udpDuplex) Write(b []byte) (int, error) { return d.w.Write(b) }
func (d *udpDuplex) Close() error                { return nil }
func (d *udpDuplex) LocalAddr() net.Addr         { return udpAddr("l") }
func (d *udpDuplex) RemoteAddr() net.Addr        { return udpAddr("r") }
func (d *udpDuplex) SetDeadline(time.Time) error { return nil }
func (d *udpDuplex) SetReadDeadline(time.Time) error {
	return nil
}
func (d *udpDuplex) SetWriteDeadline(time.Time) error { return nil }

type udpAddr string

func (a udpAddr) Network() string { return "udp-peap" }
func (a udpAddr) String() string  { return string(a) }
