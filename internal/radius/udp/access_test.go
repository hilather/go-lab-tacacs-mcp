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
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	accessTestPassword  = "labpass1!"
	accessTestChallenge = "chap-secret-16ch!"
)

func TestUDPIntegrityDiscardsDoNotMutateCache(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessUsers(t, true, true, server.Stub{})
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)

	var ra [16]byte
	ra[0] = 0x61
	valid := signAccessRequest(t, secret, codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    9,
		Authenticator: ra,
		Attributes:    attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("alice")}},
	})
	if _, err := c.Write(valid); err != nil {
		t.Fatal(err)
	}
	first := readUDP(t, c, 2*time.Second)
	if first == nil {
		t.Fatal("missing first reject")
	}
	assertAccessReject(t, first, 9, ra, secret)

	bad := append([]byte(nil), valid...)
	bad[len(bad)-1] ^= 0xff
	if _, err := c.Write(bad); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("invalid MA must be silent, got %d", len(got))
	}

	if _, err := c.Write(valid); err != nil {
		t.Fatal(err)
	}
	hit := readUDP(t, c, 2*time.Second)
	if !bytesEqual(first, hit) {
		t.Fatal("invalid MA must not purge the cached Access-Reject")
	}
}

func TestUDPPAPAndCHAPRejectPaths(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessUsers(t, true, true, nil)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0x71

	hidden, err := crypto.HideUserPassword(secret, ra, []byte(accessTestPassword))
	if err != nil {
		t.Fatal(err)
	}
	chapID := byte(0x12)
	chapResp := credentials.CHAPResponse(chapID, []byte(accessTestChallenge), ra[:])
	chapOK := append([]byte{chapID}, chapResp...)

	type tc struct {
		name  string
		id    uint8
		ra    [16]byte
		attrs attribute.RawSet
		code  codec.Code
		// empty reason means silent discard
		silent bool
	}
	cases := []tc{
		{
			name: "missing-ma",
			id:   1,
			ra:   ra,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
				{Type: attribute.TypeUserPassword, Value: hidden},
			},
			silent: true,
		},
		{
			name: "pap-good-default-deny",
			id:   2,
			ra:   ra,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
				{Type: attribute.TypeUserPassword, Value: hidden},
			},
			code: codec.CodeAccessReject,
		},
		{
			name: "pap-unknown-user",
			id:   3,
			ra:   ra,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("no-such-user")},
				{Type: attribute.TypeUserPassword, Value: hidden},
			},
			code: codec.CodeAccessReject,
		},
		{
			name: "chap-good-default-deny",
			id:   4,
			ra:   ra,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
				{Type: attribute.TypeCHAPPassword, Value: chapOK},
			},
			code: codec.CodeAccessReject,
		},
		{
			name: "chap-short",
			id:   5,
			ra:   ra,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
				{Type: attribute.TypeCHAPPassword, Value: []byte{1, 2}},
			},
			code: codec.CodeAccessReject,
		},
		{
			name: "pap-and-chap",
			id:   6,
			ra:   ra,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
				{Type: attribute.TypeUserPassword, Value: hidden},
				{Type: attribute.TypeCHAPPassword, Value: chapOK},
			},
			code: codec.CodeAccessReject,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := codec.Packet{Code: codec.CodeAccessRequest, Identifier: tc.id, Authenticator: tc.ra, Attributes: tc.attrs}
			var wire []byte
			if tc.silent {
				var err error
				wire, err = codec.Encode(pkt)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				wire = signAccessRequest(t, secret, pkt)
			}
			if _, err := c.Write(wire); err != nil {
				t.Fatal(err)
			}
			got := readUDP(t, c, 2*time.Second)
			if tc.silent {
				if got != nil {
					t.Fatalf("want silent, got %d", len(got))
				}
				return
			}
			if got == nil {
				t.Fatal("missing reply")
			}
			assertSigned(t, got, tc.code, tc.id, tc.ra, secret)
			if got[0] == byte(codec.CodeAccessAccept) {
				t.Fatal("no-policy snapshot must default-deny")
			}
		})
	}
}

func TestUDPPAPAcceptFromCompiledPolicy(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessPolicy(t)
	c := dialUDP(t, ln.Addr().String())
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0x91
	hidden, err := crypto.HideUserPassword(secret, ra, []byte(accessTestPassword))
	if err != nil {
		t.Fatal(err)
	}
	wire := signAccessRequest(t, secret, codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    7,
		Authenticator: ra,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
			{Type: attribute.TypeUserPassword, Value: hidden},
		},
	})
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("missing reply")
	}
	assertSigned(t, got, codec.CodeAccessAccept, 7, ra, secret)
	pkt, err := codec.Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Attributes[0].Type != attribute.TypeMessageAuthenticator {
		t.Fatal("Message-Authenticator must be first")
	}
	to, ok := pkt.Attributes.First(attribute.TypeSessionTimeout)
	if !ok || len(to.Value) != 4 || to.Value[0] != 0 || to.Value[1] != 0 || to.Value[2] != 0x02 || to.Value[3] != 0x58 {
		t.Fatalf("Session-Timeout=%v", to)
	}
}

func TestUDPCompatProxyStateWithoutMA(t *testing.T) {
	t.Parallel()
	ln, _ := startAccessUsers(t, false, false, nil)
	c := dialUDP(t, ln.Addr().String())
	var ra [16]byte
	ra[0] = 0x81
	hidden, err := crypto.HideUserPassword([]byte(labSecret), ra, []byte(accessTestPassword))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.Encode(codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    3,
		Authenticator: ra,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
			{Type: attribute.TypeUserPassword, Value: hidden},
			{Type: attribute.TypeProxyState, Value: []byte("ps")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("compat mode without MA must still Access-Reject")
	}
	assertAccessReject(t, got, 3, ra, []byte(labSecret))
}

func startAccessUsers(t *testing.T, requireMA, limitPS bool, h server.Handler) (*Listener, *state.Manager) {
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
	doc := mustParse(t, radiusUsersYAML(sec, login, chal, requireMA, limitPS))
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		svc, err := aaa.New(aaa.Options{
			Manager: mgr,
			Secrets: lookup,
			Events:  events.New(8, domain.SystemClock{}),
			Creds:   credentials.Options{Params: credentials.TestParams},
		})
		if err != nil {
			t.Fatal(err)
		}
		h = server.Access{AAA: svc}
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
		Handler:  h,
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

func startAccessPolicy(t *testing.T) (*Listener, *state.Manager) {
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
	doc := mustParse(t, radiusPolicyYAML(sec, login, chal))
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
	return ln, mgr
}

func radiusUsersYAML(secret, login, chal string, requireMA, limitPS bool) string {
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
          require_message_authenticator: ` + boolYAML(requireMA) + `
          limit_proxy_state: ` + boolYAML(limitPS) + `
users:
  - id: lab-admin
    credentials:
      login:
        verifier: {file: ` + login + `}
      challenge:
        secret: {file: ` + chal + `}
`
}

func radiusPolicyYAML(secret, login, chal string) string {
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
}

func boolYAML(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
