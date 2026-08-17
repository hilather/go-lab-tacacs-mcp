package udp

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestIndependentTestclientMSCHAPOnUDP(t *testing.T) {
	t.Parallel()
	ln := startAccessMSCHAP(t)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)

	var ra [16]byte
	ra[0] = 0xb1
	chal := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	tacacs := credentials.MSCHAPv1Response([]byte(accessTestChallenge), chal, true)
	v1 := radiusMSCHAPv1(9, tacacs)
	pkt, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:      21,
		Authenticator:   ra,
		UserName:        "lab-admin",
		MSCHAPChallenge: chal,
		MSCHAPResponse:  v1,
		IncludeMA:       true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(pkt); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing v1 reply")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatalf("independent client rejected v1 reply: %v", err)
	}
	if reply.Code != tcodec.AccessAccept {
		t.Fatalf("v1 code=%s", reply.Code)
	}
	if reply.HasMSCHAPError() {
		t.Fatal("v1 accept must not carry MS-CHAP-Error")
	}

	var ra2 [16]byte
	ra2[0] = 0xb2
	auth := []byte{0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e, 0x3c, 0x2c, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28}
	peer := []byte{0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29, 0x5f, 0x2b, 0x3a, 0x33, 0x7c, 0x7e}
	tacacs2 := credentials.MSCHAPv2Response([]byte(accessTestChallenge), []byte("lab-admin"), auth, peer)
	v2 := radiusMSCHAPv2(17, tacacs2)
	pkt2, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:      22,
		Authenticator:   ra2,
		UserName:        "lab-admin",
		MSCHAPChallenge: auth,
		MSCHAP2Response: v2,
		IncludeMA:       true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(pkt2); err != nil {
		t.Fatal(err)
	}
	got2 := readUDP(t, c, 2*time.Second)
	if got2 == nil {
		t.Fatal("missing v2 reply")
	}
	reply2, err := testclient.DecodeAccessReply(secret, ra2, got2)
	if err != nil {
		t.Fatalf("independent client rejected v2 reply: %v", err)
	}
	if reply2.Code != tcodec.AccessAccept {
		t.Fatalf("v2 code=%s", reply2.Code)
	}
	success, ok := reply2.MSCHAP2Success()
	if !ok || success[0] != 17 || string(success[1:3]) != "S=" {
		t.Fatalf("MS-CHAP2-Success=%x ok=%v", success, ok)
	}
	want, err := credentials.GenerateMSCHAPv2Success(17, []byte(accessTestChallenge), []byte("lab-admin"), auth, peer)
	if err != nil {
		t.Fatal(err)
	}
	if string(success) != string(want) {
		t.Fatalf("success %x want %x", success, want)
	}
}

func TestUDPPAPDefaultDoesNotEnableMSCHAP(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessPolicy(t)
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0xb3
	chal := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	tacacs := credentials.MSCHAPv1Response([]byte(accessTestChallenge), chal, true)
	pkt, err := testclient.EncodeAccessRequest([]byte(labSecret), testclient.AccessRequest{
		Identifier:      23,
		Authenticator:   ra,
		UserName:        "lab-admin",
		MSCHAPChallenge: chal,
		MSCHAPResponse:  radiusMSCHAPv1(9, tacacs),
		IncludeMA:       true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(pkt); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing reply")
	}
	reply, err := testclient.DecodeAccessReply([]byte(labSecret), ra, got)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.AccessReject {
		t.Fatalf("omitted methods must not enable MS-CHAP: %s", reply.Code)
	}
}

func radiusMSCHAPv1(ident byte, tacacs []byte) []byte {
	out := make([]byte, 50)
	out[0] = ident
	out[1] = tacacs[48]
	copy(out[2:26], tacacs[0:24])
	copy(out[26:50], tacacs[24:48])
	return out
}

func radiusMSCHAPv2(ident byte, tacacs []byte) []byte {
	out := make([]byte, 50)
	out[0] = ident
	copy(out[2:18], tacacs[0:16])
	copy(out[18:26], tacacs[16:24])
	copy(out[26:50], tacacs[24:48])
	return out
}

func startAccessMSCHAP(t *testing.T) *Listener {
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
	src := `
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
          shared_secret: {file: ` + sec + `}
          allowed_authentication_methods: [pap, chap, mschapv1, mschapv2]
          access_policy_id: default-radius-access
groups:
  - id: lab-admins
    priority: 10
users:
  - id: lab-admin
    group_ids: [lab-admins]
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
	doc := mustParse(t, src)
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
	settings := doc.Listeners.RADIUSAccess
	settings.Workers = 2
	settings.QueueCapacity = 32
	settings.WorkerDeadline = 2 * time.Second
	ln, err := Listen(Options{
		Role:     domain.RoleAccess,
		Bind:     "127.0.0.1:0",
		Required: true,
		Settings: settings,
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
		Handler:  server.Access{AAA: svc},
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
	return ln
}
