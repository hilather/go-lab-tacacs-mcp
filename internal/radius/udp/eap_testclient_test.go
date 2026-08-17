package udp

import (
	"context"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
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
	ln, err := Listen(Options{
		Role:       domain.RoleAccess,
		Bind:       "127.0.0.1:0",
		Required:   true,
		Settings:   settings,
		Snapshot:   mgr.Snapshot,
		Secrets:    lookup,
		Handler:    server.Access{AAA: svc, Store: store, Entropy: rand.Reader},
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
