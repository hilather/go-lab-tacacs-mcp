package operations

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	radiusTestPassword  = "labpass1!"
	radiusTestChallenge = "chap-secret-16ch!"
)

func TestRadiusAccessTestPAPAcceptAndWipe(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	tester := Actor{ID: "t", Scopes: []string{"policy:test"}}
	req := RadiusAccessTestRequest{
		ClientID: "lab-switches",
		UserID:   "lab-admin",
		Method:   RadiusAuthMethod{Type: "pap", Password: radiusTestPassword},
		Explain:  true,
	}
	res, err := reg.Invoke(context.Background(), IDRadiusAccessTest, m.Snapshot(), Input{Actor: tester, Request: req})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusAccessTestResult)
	if out.Outcome != RadiusOutcomeAccept || out.ReasonCode != aaa.AccessReasonOK {
		t.Fatalf("got %+v", out)
	}
	if out.Trace == nil || out.Trace.Winner == nil || out.Trace.Winner.RuleID != "permit-lab-admins" {
		t.Fatalf("trace=%+v", out.Trace)
	}
	foundTimeout := false
	for _, a := range out.ReplyAttributes {
		if a.Name == "Session-Timeout" && a.Value == "600" {
			foundTimeout = true
		}
	}
	if !foundTimeout {
		t.Fatalf("reply=%+v", out.ReplyAttributes)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), radiusTestPassword) {
		t.Fatalf("password leaked: %s", raw)
	}
}

func TestRadiusAccessTestRejectsAndDoesNotEnumerate(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	tester := Actor{ID: "t", Scopes: []string{"policy:test"}}
	snap := m.Snapshot()

	bad := RadiusAccessTestRequest{
		ClientID: "lab-switches", UserID: "lab-admin",
		Method: RadiusAuthMethod{Type: "pap", Password: "wrong-password"},
	}
	res, err := reg.Invoke(context.Background(), IDRadiusAccessTest, snap, Input{Actor: tester, Request: bad})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusAccessTestResult)
	if out.Outcome != RadiusOutcomeReject || out.ReasonCode != aaa.AccessReasonBadCredentials {
		t.Fatalf("bad pw=%+v", out)
	}

	unknown := RadiusAccessTestRequest{
		ClientID: "lab-switches", UserID: "no-such-user",
		Method: RadiusAuthMethod{Type: "pap", Password: radiusTestPassword},
	}
	res, err = reg.Invoke(context.Background(), IDRadiusAccessTest, snap, Input{Actor: tester, Request: unknown})
	if err != nil {
		t.Fatal(err)
	}
	unk := res.Data.(RadiusAccessTestResult)
	if unk.Outcome != RadiusOutcomeReject || unk.ReasonCode != aaa.AccessReasonBadCredentials {
		t.Fatalf("unknown user=%+v", unk)
	}

	deny := RadiusAccessTestRequest{
		ClientID: "lab-switches", UserID: "lab-readonly",
		Method: RadiusAuthMethod{Type: "pap", Password: radiusTestPassword}, Explain: true,
	}
	res, err = reg.Invoke(context.Background(), IDRadiusAccessTest, snap, Input{Actor: tester, Request: deny})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Data.(RadiusAccessTestResult)
	if d.Outcome != RadiusOutcomeReject || d.ReasonCode != aaa.AccessReasonPolicy {
		t.Fatalf("deny=%+v", d)
	}
	if d.Trace == nil || d.Trace.Winner == nil || d.Trace.Winner.RuleID != "deny-rest" {
		t.Fatalf("deny trace=%+v", d.Trace)
	}
}

func TestRadiusAccessTestCHAPAndAttributes(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	tester := Actor{ID: "t", Scopes: []string{"policy:test"}}
	id := byte(0x42)
	chal := []byte("12345678")
	resp := credentials.CHAPResponse(id, []byte(radiusTestChallenge), chal)
	res, err := reg.Invoke(context.Background(), IDRadiusAccessTest, m.Snapshot(), Input{
		Actor: tester,
		Request: RadiusAccessTestRequest{
			ClientID: "lab-switches",
			UserID:   "lab-admin",
			Method: RadiusAuthMethod{
				Type:      "chap",
				ID:        id,
				Challenge: base64.StdEncoding.EncodeToString(chal),
				Response:  base64.StdEncoding.EncodeToString(resp),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusAccessTestResult)
	if out.Outcome != RadiusOutcomeAccept {
		t.Fatalf("chap=%+v", out)
	}

	res, err = reg.Invoke(context.Background(), IDRadiusAccessTest, m.Snapshot(), Input{
		Actor: tester,
		Request: RadiusAccessTestRequest{
			ClientID: "lab-switches",
			UserID:   "lab-readonly",
			Method:   RadiusAuthMethod{Type: "pap", Password: radiusTestPassword},
			RequestAttributes: []RadiusAttributeValue{
				{Name: "NAS-Identifier", Value: "edge-1"},
				{Name: "Service-Type", Value: "Login-User"},
			},
			Explain: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	attr := res.Data.(RadiusAccessTestResult)
	if attr.Outcome != RadiusOutcomeAccept || attr.Trace == nil || attr.Trace.Winner == nil || attr.Trace.Winner.RuleID != "permit-pap-nas" {
		t.Fatalf("attr match=%+v", attr)
	}
}

func TestRadiusAccessTestMSCHAPAndPolicyEvaluate(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	tester := Actor{ID: "t", Scopes: []string{"policy:test"}}
	auth := []byte{0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e, 0x3c, 0x2c, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28}
	peer := []byte{0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29, 0x5f, 0x2b, 0x3a, 0x33, 0x7c, 0x7e}
	resp := credentials.MSCHAPv2Response([]byte(radiusTestChallenge), []byte("lab-admin"), auth, peer)
	res, err := reg.Invoke(context.Background(), IDRadiusAccessTest, m.Snapshot(), Input{
		Actor: tester,
		Request: RadiusAccessTestRequest{
			ClientID: "lab-switches",
			UserID:   "lab-admin",
			Method: RadiusAuthMethod{
				Type:      "mschapv2",
				ID:        17,
				Challenge: base64.StdEncoding.EncodeToString(auth),
				Response:  base64.StdEncoding.EncodeToString(resp),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusAccessTestResult)
	if out.Outcome != RadiusOutcomeAccept {
		t.Fatalf("mschapv2=%+v", out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "S=") || strings.Contains(strings.ToLower(string(raw)), "ms-chap") {
		t.Fatalf("MS-CHAP2-Success leaked: %s", raw)
	}

	eval, err := reg.Invoke(context.Background(), IDRadiusPolicyEvaluate, m.Snapshot(), Input{
		Actor: tester,
		Request: RadiusPolicyEvaluateRequest{
			ClientID: "lab-switches",
			UserID:   "lab-admin",
			Method:   "mschapv2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := eval.Data.(RadiusPolicyEvaluateResult)
	if got.Effect != domain.EffectPermit.String() {
		t.Fatalf("evaluate mschapv2=%+v", got)
	}
}

func TestRadiusAccessTestMustChangeReasonCode(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	writer := Actor{ID: "w", Scopes: []string{"state:write"}}
	tester := Actor{ID: "t", Scopes: []string{"policy:test"}}
	rev := m.Revision()
	_, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          UpdateUserRequest{ID: "lab-admin", MustChangeLogin: boolPtr(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := reg.Invoke(context.Background(), IDRadiusAccessTest, m.Snapshot(), Input{
		Actor: tester,
		Request: RadiusAccessTestRequest{
			ClientID: "lab-switches",
			UserID:   "lab-admin",
			Method:   RadiusAuthMethod{Type: "pap", Password: radiusTestPassword},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusAccessTestResult)
	if out.Outcome != RadiusOutcomeReject || out.ReasonCode != aaa.AccessReasonPasswordChangeRequired {
		t.Fatalf("got %+v", out)
	}
}

func TestRadiusAccessTestValidationAndScope(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	snap := m.Snapshot()
	tester := Actor{ID: "t", Scopes: []string{"policy:test"}}

	_, err := reg.Invoke(context.Background(), IDRadiusAccessTest, snap, Input{
		Actor: reader, Request: RadiusAccessTestRequest{UserID: "lab-admin", Method: RadiusAuthMethod{Type: "pap"}},
	})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("scope err=%v", err)
	}
	_, err = reg.Invoke(context.Background(), IDRadiusAccessTest, snap, Input{
		Actor: tester, Request: RadiusAccessTestRequest{Method: RadiusAuthMethod{Type: "pap"}},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("user err=%v", err)
	}
	_, err = reg.Invoke(context.Background(), IDRadiusAccessTest, snap, Input{
		Actor: tester, Request: RadiusAccessTestRequest{UserID: "lab-admin", Method: RadiusAuthMethod{Type: "password"}},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("method err=%v", err)
	}
	_, err = reg.Invoke(context.Background(), IDRadiusAccessTest, snap, Input{
		Actor: tester, Request: RadiusAccessTestRequest{
			UserID: "lab-admin", ClientID: "missing", Method: RadiusAuthMethod{Type: "pap", Password: "x"},
		},
	})
	if !isCode(err, domain.CodeNotFound) {
		t.Fatalf("client err=%v", err)
	}
	_, err = reg.Invoke(context.Background(), IDRadiusAccessTest, snap, Input{
		Actor: tester, Request: RadiusAccessTestRequest{
			UserID: "lab-admin", Method: RadiusAuthMethod{Type: "pap"},
			RequestAttributes: []RadiusAttributeValue{{Name: "User-Password", Value: "secret"}},
		},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("secret attr err=%v", err)
	}
}

func TestRadiusAccessTestNilAAAFailClosed(t *testing.T) {
	t.Parallel()
	m := mustRadiusMgr(t)
	reg, err := New(mustSpec(t), Deps{State: m})
	if err != nil {
		t.Fatal(err)
	}
	res, err := reg.Invoke(context.Background(), IDRadiusAccessTest, m.Snapshot(), Input{
		Actor:   Actor{ID: "t", Scopes: []string{"policy:test"}},
		Request: RadiusAccessTestRequest{UserID: "lab-admin", Method: RadiusAuthMethod{Type: "pap", Password: radiusTestPassword}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusAccessTestResult)
	if out.Outcome != RadiusOutcomeReject || out.ReasonCode != aaa.AccessReasonInternal {
		t.Fatalf("got %+v", out)
	}
}

func TestRadiusPolicyEvaluateSameEngine(t *testing.T) {
	t.Parallel()
	reg, m := radiusTestRegistry(t)
	tester := Actor{ID: "t", Scopes: []string{"policy:test"}}
	snap := m.Snapshot()

	res, err := reg.Invoke(context.Background(), IDRadiusPolicyEvaluate, snap, Input{
		Actor: tester,
		Request: RadiusPolicyEvaluateRequest{
			ClientID: "lab-switches", UserID: "lab-admin", Method: "pap",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusPolicyEvaluateResult)
	if out.Effect != domain.EffectPermit.String() || out.ReasonCode != aaa.AccessReasonOK {
		t.Fatalf("got %+v", out)
	}
	if out.Trace.Evaluator != "radius_access" || out.Trace.Winner == nil || out.Trace.Winner.RuleID != "permit-lab-admins" {
		t.Fatalf("trace=%+v", out.Trace)
	}
	found := false
	for _, a := range out.ReplyAttributes {
		if a.Name == "Session-Timeout" && a.Value == "600" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reply=%+v", out.ReplyAttributes)
	}

	res, err = reg.Invoke(context.Background(), IDRadiusPolicyEvaluate, snap, Input{
		Actor: tester,
		Request: RadiusPolicyEvaluateRequest{
			ClientID: "lab-switches", UserID: "nobody", Method: "chap",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	deny := res.Data.(RadiusPolicyEvaluateResult)
	if deny.Effect != domain.EffectDeny.String() {
		t.Fatalf("default deny=%+v", deny)
	}
}

func TestRadiusAttributesListMetadataOnly(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	res, err := reg.Invoke(context.Background(), IDRadiusAttributesList, mustSnap(t, smallYAML), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusAttributeList)
	if out.Version != attribute.DictionaryVersion || len(out.Items) == 0 {
		t.Fatalf("list=%+v", out)
	}
	var sawUser, sawPW, sawMA bool
	for _, it := range out.Items {
		if it.Name == "User-Name" {
			sawUser = true
			if it.Code != 1 || it.ValueKind == "" || len(it.AllowedIn) == 0 || it.Source != attribute.SourceBuiltin {
				t.Fatalf("user-name=%+v", it)
			}
		}
		if it.Name == "User-Password" {
			sawPW = true
			if it.Sensitivity != string(attribute.SensitivitySecret) {
				t.Fatalf("password sensitivity=%+v", it)
			}
		}
		if it.Name == "Message-Authenticator" {
			sawMA = true
		}
	}
	if !sawUser || !sawPW || !sawMA {
		t.Fatalf("missing defs user=%v pw=%v ma=%v n=%d", sawUser, sawPW, sawMA, len(out.Items))
	}
	raw, _ := json.Marshal(out)
	for _, needle := range []string{"labpass", "verifier", "password-value"} {
		if strings.Contains(strings.ToLower(string(raw)), needle) {
			t.Fatalf("dictionary leaked %q: %s", needle, raw)
		}
	}
}

func TestRadiusAttributesListOperatorSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "juniper.yaml")
	if err := os.WriteFile(path, []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes:
  - name: Juniper-Local-User-Name
    vendor_type: 1
    kind: text
    sensitivity: restricted
    allowed_in: [access_accept]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := mustSnap(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: lab-juniper
    file: `+path+`
`)
	reg := mustRegistry(t)
	res, err := reg.Invoke(context.Background(), IDRadiusAttributesList, snap, Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(RadiusAttributeList)
	if !strings.HasPrefix(out.Version, attribute.DictionaryVersion+"+op:") {
		t.Fatalf("version=%q", out.Version)
	}
	var sawOp, sawBuiltin bool
	for _, it := range out.Items {
		if it.Name == "Juniper-Local-User-Name" {
			sawOp = true
			if it.Source != "operator:lab-juniper" || it.Vendor != 2636 || it.Code != 1 {
				t.Fatalf("op=%+v", it)
			}
		}
		if it.Name == "User-Name" && it.Source == attribute.SourceBuiltin {
			sawBuiltin = true
		}
	}
	if !sawOp || !sawBuiltin {
		t.Fatalf("sawOp=%v sawBuiltin=%v n=%d", sawOp, sawBuiltin, len(out.Items))
	}
}

func TestRadiusAttributesListRequiresReadScope(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	_, err := reg.Invoke(context.Background(), IDRadiusAttributesList, mustSnap(t, smallYAML), Input{
		Actor: Actor{ID: "t", Scopes: []string{"policy:test"}},
	})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("err=%v", err)
	}
}

func radiusTestRegistry(t *testing.T) (*Registry, *state.Manager) {
	t.Helper()
	m := mustRadiusMgr(t)
	svc, err := aaa.New(aaa.Options{
		Manager: m,
		Secrets: radiusLookup,
		Events:  events.New(16, domain.SystemClock{}),
		Creds:   credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := New(mustSpec(t), Deps{State: m, AAA: svc, Events: events.New(8, nil)})
	if err != nil {
		t.Fatal(err)
	}
	return reg, m
}

func radiusLookup(ref config.SecretRef) ([]byte, error) {
	b, err := os.ReadFile(ref.File)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), b...), nil
}

func mustRadiusMgr(t *testing.T) *state.Manager {
	t.Helper()
	dir := t.TempDir()
	phc, err := credentials.DeriveArgon2id([]byte(radiusTestPassword), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	login := filepath.Join(dir, "login")
	chal := filepath.Join(dir, "chal")
	sec := filepath.Join(dir, "shared")
	for _, f := range []struct {
		path string
		data []byte
	}{
		{login, phc},
		{chal, []byte(radiusTestChallenge)},
		{sec, []byte("LabSecret-16chars!")},
	} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := `
schema_version: 2
server:
  instance_id: radius-diag
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
          allowed_authentication_methods: [pap, chap, mschapv1, mschapv2]
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
	m, err := state.New(doc, state.Options{
		Clock:   fixedClock{t: time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC)},
		Secrets: radiusLookup,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
