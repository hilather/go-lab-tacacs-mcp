package aaa

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	policyradius "github.com/hilather/go-lab-tacacs-mcp/internal/policy/radius"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestAuthenticateAccessDefaultDenyAndRejects(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	chapID := byte(0x42)
	chapChal := []byte("12345678")
	chapOK := credentials.CHAPResponse(chapID, []byte(testChallenge), chapChal)

	type tc struct {
		name   string
		user   string
		ev     CredentialEvidence
		want   RadiusAccessOutcome
		reason string
	}
	cases := []tc{
		{
			name: "pap-pass-default-deny",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte(testPassword)),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonPolicy,
		},
		{
			name: "pap-wrong-password",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte("wrong-password")),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonBadCredentials,
		},
		{
			name: "pap-unknown-user",
			user: "no-such-user",
			ev: CredentialEvidence{
				Method:   domain.AuthMethodPassword,
				Password: credentials.NewPassword([]byte(testPassword)),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonBadCredentials,
		},
		{
			name: "chap-pass-default-deny",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    chapID,
				Challenge: chapChal,
				Response:  chapOK,
			},
			want:   RadiusAccessReject,
			reason: AccessReasonPolicy,
		},
		{
			name: "chap-wrong-response",
			user: "lab-admin",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    chapID,
				Challenge: chapChal,
				Response:  make([]byte, credentials.CHAPResponseLen),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonBadCredentials,
		},
		{
			name: "chap-no-challenge-secret",
			user: "lab-readonly",
			ev: CredentialEvidence{
				Method:    domain.AuthMethodCHAP,
				CHAPID:    1,
				Challenge: []byte("12345678"),
				Response:  credentials.CHAPResponse(1, []byte(testPassword), []byte("12345678")),
			},
			want:   RadiusAccessReject,
			reason: AccessReasonBadCredentials,
		},
		{
			name:   "unsupported-method",
			user:   "lab-admin",
			ev:     CredentialEvidence{Method: domain.AuthMethod("mschapv1")},
			want:   RadiusAccessReject,
			reason: AccessReasonUnsupportedMethod,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.AuthenticateAccess(ctx, RadiusAccessAttempt{
				Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches"},
				UserID:   tc.user,
				Evidence: tc.ev,
			})
			if err != nil {
				t.Fatalf("AuthenticateAccess: %v", err)
			}
			if got.Outcome != tc.want || got.ReasonCode != tc.reason {
				t.Fatalf("got %+v want outcome=%s reason=%s", got, tc.want, tc.reason)
			}
			if got.Outcome == RadiusAccessAccept {
				t.Fatal("v1 snapshot has no RADIUS policy; must default-deny")
			}
		})
	}
}

func TestAuthenticateAccessPermitFromCompiledPolicy(t *testing.T) {
	t.Parallel()
	svc := testRADIUSPolicyService(t)
	got, err := svc.AuthenticateAccess(context.Background(), RadiusAccessAttempt{
		Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches", EndpointID: "radius-udp"},
		UserID:   "lab-admin",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword, Password: credentials.NewPassword([]byte(testPassword))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != RadiusAccessAccept || got.ReasonCode != AccessReasonOK {
		t.Fatalf("got %+v", got)
	}
	if got.Trace.Winner == nil || got.Trace.Winner.RuleID != "permit-lab-admins" {
		t.Fatalf("trace=%+v", got.Trace)
	}
	if timeout := firstAttr(got.ReplyAttributes, attribute.TypeSessionTimeout); timeout == nil || binary.BigEndian.Uint32(timeout.Value) != 600 {
		t.Fatalf("Session-Timeout=%v", got.ReplyAttributes)
	}

	chapID := byte(0x42)
	chapChal := []byte("12345678")
	chapOK := credentials.CHAPResponse(chapID, []byte(testChallenge), chapChal)
	got, err = svc.AuthenticateAccess(context.Background(), RadiusAccessAttempt{
		Context: domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches", EndpointID: "radius-udp"},
		UserID:  "lab-admin",
		Evidence: CredentialEvidence{
			Method:    domain.AuthMethodCHAP,
			CHAPID:    chapID,
			Challenge: chapChal,
			Response:  chapOK,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != RadiusAccessAccept || got.ReasonCode != AccessReasonOK {
		t.Fatalf("chap permit got %+v", got)
	}
}

func TestAuthenticateAccessDenyFromCompiledPolicy(t *testing.T) {
	t.Parallel()
	svc := testRADIUSPolicyService(t)
	got, err := svc.AuthenticateAccess(context.Background(), RadiusAccessAttempt{
		Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches", EndpointID: "radius-udp"},
		UserID:   "lab-readonly",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword, Password: credentials.NewPassword([]byte(testPassword))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != RadiusAccessReject || got.ReasonCode != AccessReasonPolicy {
		t.Fatalf("got %+v", got)
	}
	if got.Trace.Winner == nil || got.Trace.Winner.RuleID != "deny-rest" {
		t.Fatalf("trace=%+v", got.Trace)
	}
	if msg := firstAttr(got.ReplyAttributes, attribute.TypeReplyMessage); msg == nil || string(msg.Value) != "denied" {
		t.Fatalf("Reply-Message=%v", got.ReplyAttributes)
	}
}

func TestAuthenticateAccessAttributeMatchPermit(t *testing.T) {
	t.Parallel()
	svc := testRADIUSPolicyService(t)
	var serviceType [4]byte
	binary.BigEndian.PutUint32(serviceType[:], 1)
	got, err := svc.AuthenticateAccess(context.Background(), RadiusAccessAttempt{
		Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches", EndpointID: "radius-udp"},
		UserID:   "lab-readonly",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword, Password: credentials.NewPassword([]byte(testPassword))},
		Attributes: attribute.RawSet{
			{Type: attribute.TypeNASIdentifier, Value: []byte("edge-1")},
			{Type: attribute.TypeServiceType, Value: serviceType[:]},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != RadiusAccessAccept || got.Trace.Winner == nil || got.Trace.Winner.RuleID != "permit-pap-nas" {
		t.Fatalf("got %+v", got)
	}
}

func TestAuthenticateAccessPolicyErrorRejects(t *testing.T) {
	t.Parallel()
	got := mapPolicyResult("lab-admin", policyradius.Result{
		Effect: domain.EffectError,
		Trace:  policyradius.Trace{Error: "policy engine is not compiled", Effect: domain.EffectError.String()},
	})
	if got.Outcome != RadiusAccessReject || got.ReasonCode != AccessReasonInternal {
		t.Fatalf("evaluator error must Access-Reject: %+v", got)
	}
	if got.Outcome == RadiusAccessAccept {
		t.Fatal("must not accept")
	}
}

func testRADIUSPolicyService(t testing.TB) *Service {
	t.Helper()
	dir := t.TempDir()
	phc := testPHC(t)
	chal := filepath.Join(dir, "chal")
	login := filepath.Join(dir, "login")
	sec := filepath.Join(dir, "shared")
	for _, f := range []struct {
		path string
		data []byte
	}{
		{login, phc},
		{chal, []byte(testChallenge)},
		{sec, []byte(testSecret)},
	} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := `
schema_version: 2
server:
  instance_id: radius-policy
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  radius:
    access: {enabled: true, bind: 127.0.0.1:0}
  http: {enabled: true, bind: 127.0.0.1:0}
clients:
  - id: lab-switches
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
          access_policy_id: default-radius-access
groups:
  - id: lab-admins
    priority: 10
  - id: readonly
    priority: 100
users:
  - id: lab-admin
    group_ids: [lab-admins]
    credentials:
      login:
        verifier: {file: ` + login + `}
      challenge:
        secret: {file: ` + chal + `}
  - id: lab-readonly
    group_ids: [readonly]
    credentials:
      login:
        verifier: {file: ` + login + `}
radius_reply_profiles:
  - id: lab-accept
    attributes:
      - name: Session-Timeout
        value: "600"
  - id: reject-msg
    attributes:
      - name: Reply-Message
        value: denied
radius_policies:
  - id: default-radius-access
    rules:
      - id: permit-lab-admins
        match:
          groups_any: [lab-admins]
        effect: permit
        reply_profiles: [lab-accept]
      - id: permit-pap-nas
        match:
          method: pap
          attributes:
            - name: NAS-Identifier
              op: equals
              value: edge-1
            - name: Service-Type
              op: present
            - name: Calling-Station-Id
              op: absent
        effect: permit
        reply_profiles: [lab-accept]
      - id: deny-rest
        effect: deny
        reply_profiles: [reject-msg]
`
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) {
		b, err := os.ReadFile(ref.File)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	}
	mgr, err := state.New(doc, state.Options{
		Clock:   fixedClock{t: time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC)},
		Secrets: lookup,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Options{
		Manager: mgr,
		Secrets: lookup,
		Events:  events.New(32, domain.SystemClock{}),
		Creds:   credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func firstAttr(set attribute.RawSet, typ uint8) *attribute.Raw {
	if a, ok := set.First(typ); ok {
		return &a
	}
	return nil
}

func TestPolicyRequestAttrsSkipSecrets(t *testing.T) {
	t.Parallel()
	var serviceType [4]byte
	binary.BigEndian.PutUint32(serviceType[:], 1)
	got := policyRequestAttrs(attribute.RawSet{
		{Type: attribute.TypeUserPassword, Value: []byte("secret")},
		{Type: attribute.TypeNASIdentifier, Value: []byte("edge-1")},
		{Type: attribute.TypeServiceType, Value: serviceType[:]},
		{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
		{Type: attribute.TypeProxyState, Value: []byte("ps")},
	})
	if len(got) != 2 || got[0].Text != "edge-1" || got[1].Uint != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestEncodePolicyReplyRejectsIllegalRole(t *testing.T) {
	t.Parallel()
	_, err := encodePolicyReply(policyradius.TypedSet{{
		Key:  policyradius.AttrKey{Name: "NAS-IP-Address", Code: 4},
		Kind: policyradius.KindIPv4,
		Addr: netip.MustParseAddr("192.0.2.1"),
	}}, attribute.PacketAccessAccept)
	if err == nil {
		t.Fatal("expected illegal role")
	}
}

func TestAuthenticateAccessWipesPassword(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	pw := credentials.NewPassword([]byte(testPassword))
	in := RadiusAccessAttempt{
		Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches"},
		UserID:   "lab-admin",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword, Password: pw},
	}
	if strings.Contains(fmt.Sprintf("%v", in), testPassword) {
		t.Fatal("password leaked from RadiusAccessAttempt formatting")
	}
	got, err := svc.AuthenticateAccess(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != RadiusAccessReject || got.ReasonCode != AccessReasonPolicy {
		t.Fatalf("got %+v", got)
	}
	for _, b := range pw.Bytes() {
		if b != 0 {
			t.Fatal("password holder backing bytes were not wiped")
		}
	}
}

func TestAuthenticateAccessCancelledContext(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := svc.AuthenticateAccess(ctx, RadiusAccessAttempt{
		Context:  domain.RequestContext{Protocol: domain.ProtocolRADIUS, ClientID: "lab-switches"},
		UserID:   "lab-admin",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword, Password: credentials.NewPassword([]byte(testPassword))},
	})
	if err == nil || got.Outcome != RadiusAccessReject {
		t.Fatalf("cancelled ctx outcome=%s err=%v", got.Outcome, err)
	}
}

func TestAuthenticateAccessNilService(t *testing.T) {
	t.Parallel()
	var svc *Service
	got, err := svc.AuthenticateAccess(context.Background(), RadiusAccessAttempt{
		UserID:   "lab-admin",
		Evidence: CredentialEvidence{Method: domain.AuthMethodPassword},
	})
	if got.Outcome != RadiusAccessReject || got.ReasonCode != AccessReasonInternal {
		t.Fatalf("got %+v", got)
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeInternal {
		t.Fatalf("err=%v", err)
	}
}
