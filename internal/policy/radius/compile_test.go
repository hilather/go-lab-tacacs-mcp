package radius

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestCompileStoresPAPAsPassword(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
fallback_radius_policy_id: p
radius_policies:
  - id: p
    rules:
      - id: pap
        match:
          method: pap
        effect: deny
`)
	doc, err := config.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(doc); err != nil {
		t.Fatal(err)
	}
	rule := doc.RADIUSPolicies[0].Rules[0]
	if rule.Match.Method == nil || *rule.Match.Method != domain.AuthMethodPassword {
		t.Fatalf("pap must store password, got %#v", rule.Match.Method)
	}
	eng, err := CompileDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	res := eng.Evaluate(Request{ClientID: "", Method: domain.AuthMethodPassword})
	if res.Effect != domain.EffectDeny || res.Trace.Winner == nil {
		t.Fatalf("password must match pap rule: %+v", res)
	}
	res = eng.Evaluate(Request{Method: domain.AuthMethodCHAP})
	if res.Trace.Winner != nil {
		t.Fatalf("chap must not match pap-stored password rule: %+v", res)
	}
}

func TestCompileRejectsPasswdMethod(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
radius_policies:
  - id: p
    rules:
      - id: bad
        match:
          method: passwd
        effect: deny
`)
	_, err := config.Parse(src)
	if err == nil {
		t.Fatal("expected passwd to fail")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "radius_policies.p.rules.bad.match.method") {
		t.Fatalf("path=%q", de.Path)
	}
	msg := strings.ToLower(de.Message)
	for _, tok := range []string{"password", "pap", "chap", "mschapv1", "mschapv2", "eap"} {
		if !strings.Contains(msg, tok) {
			t.Fatalf("message must name %q: %q", tok, de.Message)
		}
	}
}

func TestCompileUnknownAttributeName(t *testing.T) {
	t.Parallel()
	in := Input{Policies: []config.RADIUSPolicy{{
		ID: "p",
		Rules: []config.RADIUSRule{{
			ID:      "r",
			Enabled: true,
			Effect:  domain.EffectDeny,
			Match: config.RADIUSMatch{Attributes: []config.RADIUSAttrMatch{{
				Name: "Juniper-Local-User-Name",
				Op:   config.RADIUSMatchOpPresent,
			}}},
		}},
	}}}
	_, err := Compile(in)
	if err == nil {
		t.Fatal("expected unknown name")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "name") {
		t.Fatalf("path=%q", de.Path)
	}
}

func TestCompileRejectsSecretMatchKey(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"User-Password", "CHAP-Password", "Message-Authenticator", "State"} {
		_, err := Compile(Input{Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:      "r",
				Enabled: true,
				Effect:  domain.EffectDeny,
				Match: config.RADIUSMatch{Attributes: []config.RADIUSAttrMatch{{
					Name: name,
					Op:   config.RADIUSMatchOpPresent,
				}}},
			}},
		}}})
		if err == nil {
			t.Fatalf("%s must not be a match key", name)
		}
	}
}

func TestCompileRejectsIllegalReplyRole(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		ReplyProfiles: []config.RADIUSReplyProfile{{
			ID:         "bad",
			Attributes: []config.RADIUSReplyAttr{{Name: "NAS-IP-Address", Value: "192.0.2.1"}},
		}},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:            "r",
				Enabled:       true,
				Effect:        domain.EffectPermit,
				ReplyProfiles: []string{"bad"},
			}},
		}},
	})
	if err == nil {
		t.Fatal("NAS-IP-Address is not legal on Access-Accept")
	}
	de, _ := domain.AsError(err)
	if de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
}

func TestCompileDenyReplyOnlyReplyMessage(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		ReplyProfiles: []config.RADIUSReplyProfile{{
			ID:         "to",
			Attributes: []config.RADIUSReplyAttr{{Name: "Session-Timeout", Value: "60"}},
		}},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:            "r",
				Enabled:       true,
				Effect:        domain.EffectDeny,
				ReplyProfiles: []string{"to"},
			}},
		}},
	})
	if err == nil {
		t.Fatal("deny must not emit Session-Timeout")
	}
}

func TestCompileDenyReplyRejectsRawVSA(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		ReplyProfiles: []config.RADIUSReplyProfile{{
			ID: "vsa",
			Attributes: []config.RADIUSReplyAttr{{
				Vendor:   9,
				Code:     1,
				ValueHex: "666f6f",
			}},
		}},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:            "r",
				Enabled:       true,
				Effect:        domain.EffectDeny,
				ReplyProfiles: []string{"vsa"},
			}},
		}},
	})
	if err == nil {
		t.Fatal("deny must not emit raw VSA")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Message, "Reply-Message") {
		t.Fatalf("message=%q", de.Message)
	}
}

func TestCompileRejectsUnknownUserRADIUSPolicyID(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		Users: []config.User{{ID: "u", Enabled: true, RADIUSPolicyID: "missing"}},
	})
	if err == nil {
		t.Fatal("expected unknown user policy")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "radius_policy_id") {
		t.Fatalf("path=%q", de.Path)
	}
}

func TestCompileRejectsUnknownGroupRADIUSPolicyID(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		Groups: []config.Group{{ID: "g", Enabled: true, RADIUSPolicyID: "missing"}},
	})
	if err == nil {
		t.Fatal("expected unknown group policy")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "groups.g.radius_policy_id") {
		t.Fatalf("path=%q", de.Path)
	}
}

func TestCompileDuplicateSingleCardinality(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		ReplyProfiles: []config.RADIUSReplyProfile{
			{ID: "a", Attributes: []config.RADIUSReplyAttr{{Name: "Session-Timeout", Value: "30"}}},
			{ID: "b", Attributes: []config.RADIUSReplyAttr{{Name: "Session-Timeout", Value: "60"}}},
		},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:            "r",
				Enabled:       true,
				Effect:        domain.EffectPermit,
				ReplyProfiles: []string{"a", "b"},
			}},
		}},
	})
	if err == nil {
		t.Fatal("duplicate single attr must fail")
	}
}

func TestCompileMultiCardinalityAllowsDuplicates(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{
		ReplyProfiles: []config.RADIUSReplyProfile{
			{ID: "a", Attributes: []config.RADIUSReplyAttr{{Name: "Reply-Message", Value: "one"}}},
			{ID: "b", Attributes: []config.RADIUSReplyAttr{{Name: "Reply-Message", Value: "two"}}},
		},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID: "r", Enabled: true, Effect: domain.EffectPermit, ReplyProfiles: []string{"a", "b"},
			}},
		}},
		Clients: []config.Client{{
			ID: "c", Enabled: true,
			Endpoints: []config.ClientEndpoint{{
				ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "p"},
			}},
		}},
	})
	res := eng.Evaluate(Request{ClientID: "c", EndpointID: "e"})
	if res.Effect != domain.EffectPermit || len(res.ReplyAttributes) != 2 {
		t.Fatalf("multi Reply-Message must merge: %+v", res)
	}
}

func TestCompileSingleCardinalitySameProfileTwice(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		ReplyProfiles: []config.RADIUSReplyProfile{
			{ID: "a", Attributes: []config.RADIUSReplyAttr{{Name: "Session-Timeout", Value: "30"}}},
		},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID: "r", Enabled: true, Effect: domain.EffectPermit, ReplyProfiles: []string{"a", "a"},
			}},
		}},
	})
	if err == nil {
		t.Fatal("same single attr from repeated profile must fail")
	}
}

func TestCompileSkipsDisabledRules(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{Policies: []config.RADIUSPolicy{{
		ID: "p",
		Rules: []config.RADIUSRule{
			{ID: "off", Enabled: false, Effect: domain.EffectPermit},
			{ID: "on", Enabled: true, Effect: domain.EffectDeny},
		},
	}}, Clients: []config.Client{{
		ID:      "c",
		Enabled: true,
		Endpoints: []config.ClientEndpoint{{
			ID:       "e",
			Protocol: domain.ProtocolRADIUS,
			RADIUS:   &config.RADIUSEndpoint{AccessPolicyID: "p"},
		}},
	}}})
	res := eng.Evaluate(Request{ClientID: "c", EndpointID: "e"})
	if res.Effect != domain.EffectDeny || res.Trace.Winner == nil || res.Trace.Winner.RuleID != "on" {
		t.Fatalf("%+v", res)
	}
	for _, s := range res.Trace.Steps {
		if s.RuleID == "off" {
			t.Fatalf("disabled rule must not appear: %+v", s)
		}
	}
}

func TestCompileNamedCiscoAVPairReply(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{
		ReplyProfiles: []config.RADIUSReplyProfile{{
			ID: "cisco",
			Attributes: []config.RADIUSReplyAttr{{
				Name:  "Cisco-AVPair",
				Value: "shell:priv-lvl=15",
			}},
		}},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:            "r",
				Enabled:       true,
				Effect:        domain.EffectPermit,
				ReplyProfiles: []string{"cisco"},
			}},
		}},
		Clients: []config.Client{{
			ID:        "c",
			Enabled:   true,
			Endpoints: []config.ClientEndpoint{{ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "p"}}},
		}},
	})
	res := eng.Evaluate(Request{ClientID: "c"})
	if res.Effect != domain.EffectPermit || len(res.ReplyAttributes) != 1 {
		t.Fatalf("%+v", res)
	}
	got := res.ReplyAttributes[0]
	if got.Key.Vendor != 9 || got.Key.Code != 1 || got.Key.Name != "Cisco-AVPair" ||
		got.Kind != KindText || got.Text != "shell:priv-lvl=15" || string(got.Raw) != "shell:priv-lvl=15" {
		t.Fatalf("named=%+v", got)
	}
}

func TestCompileNamedAndRawCiscoAVPairSameKey(t *testing.T) {
	t.Parallel()
	named := mustCompile(t, ciscoReplyInput(config.RADIUSReplyAttr{
		Name:  "Cisco-AVPair",
		Value: "shell:priv-lvl=15",
	}))
	raw := mustCompile(t, ciscoReplyInput(config.RADIUSReplyAttr{
		Vendor:   9,
		Code:     1,
		ValueHex: "7368656c6c3a707269762d6c766c3d3135",
	}))
	n := named.Evaluate(Request{ClientID: "c"}).ReplyAttributes
	r := raw.Evaluate(Request{ClientID: "c"}).ReplyAttributes
	if len(n) != 1 || len(r) != 1 {
		t.Fatalf("named=%+v raw=%+v", n, r)
	}
	if n[0].Key.Vendor != r[0].Key.Vendor || n[0].Key.Code != r[0].Key.Code || string(n[0].Raw) != string(r[0].Raw) {
		t.Fatalf("named=%+v raw=%+v", n[0], r[0])
	}
}

func TestCompileDenyReplyRejectsNamedCiscoAVPair(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		ReplyProfiles: []config.RADIUSReplyProfile{{
			ID:         "cisco",
			Attributes: []config.RADIUSReplyAttr{{Name: "Cisco-AVPair", Value: "shell:priv-lvl=15"}},
		}},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:            "r",
				Enabled:       true,
				Effect:        domain.EffectDeny,
				ReplyProfiles: []string{"cisco"},
			}},
		}},
	})
	if err == nil {
		t.Fatal("deny must not emit Cisco-AVPair")
	}
}

func TestCompileMatchCiscoAVPairEquals(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:      "r",
				Enabled: true,
				Effect:  domain.EffectPermit,
				Match: config.RADIUSMatch{Attributes: []config.RADIUSAttrMatch{{
					Name:  "Cisco-AVPair",
					Op:    config.RADIUSMatchOpEquals,
					Value: "shell:priv-lvl=15",
				}}},
			}},
		}},
		Clients: []config.Client{{
			ID:        "c",
			Enabled:   true,
			Endpoints: []config.ClientEndpoint{{ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "p"}}},
		}},
	})
	hit := eng.Evaluate(Request{ClientID: "c", Attributes: TypedSet{{
		Key:  AttrKey{Vendor: 9, Code: 1, Name: "Cisco-AVPair"},
		Kind: KindText,
		Text: "shell:priv-lvl=15",
		Raw:  []byte("shell:priv-lvl=15"),
	}}})
	if hit.Effect != domain.EffectPermit {
		t.Fatalf("want permit, got %+v", hit)
	}
	miss := eng.Evaluate(Request{ClientID: "c"})
	if miss.Effect != domain.EffectDeny {
		t.Fatalf("missing AVPair must not match: %+v", miss)
	}
}

func TestCompileCiscoAVPairNameVendorDisagree(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{
		ReplyProfiles: []config.RADIUSReplyProfile{{
			ID: "bad",
			Attributes: []config.RADIUSReplyAttr{{
				Name:   "Cisco-AVPair",
				Vendor: 311,
				Code:   1,
				Value:  "x",
			}},
		}},
		Policies: []config.RADIUSPolicy{{
			ID:    "p",
			Rules: []config.RADIUSRule{{ID: "r", Enabled: true, Effect: domain.EffectPermit, ReplyProfiles: []string{"bad"}}},
		}},
	})
	if err == nil {
		t.Fatal("vendor 311 is not Cisco-AVPair")
	}
}

func ciscoReplyInput(attr config.RADIUSReplyAttr) Input {
	return Input{
		ReplyProfiles: []config.RADIUSReplyProfile{{ID: "vsa", Attributes: []config.RADIUSReplyAttr{attr}}},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID: "r", Enabled: true, Effect: domain.EffectPermit, ReplyProfiles: []string{"vsa"},
			}},
		}},
		Clients: []config.Client{{
			ID:        "c",
			Enabled:   true,
			Endpoints: []config.ClientEndpoint{{ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "p"}}},
		}},
	}
}

func TestCompileRawVSAReply(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{
		ReplyProfiles: []config.RADIUSReplyProfile{{
			ID: "vsa",
			Attributes: []config.RADIUSReplyAttr{{
				Vendor:   9,
				Code:     1,
				ValueHex: "666f6f",
			}},
		}},
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{{
				ID:            "r",
				Enabled:       true,
				Effect:        domain.EffectPermit,
				ReplyProfiles: []string{"vsa"},
			}},
		}},
		Clients: []config.Client{{
			ID:        "c",
			Enabled:   true,
			Endpoints: []config.ClientEndpoint{{ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "p"}}},
		}},
	})
	res := eng.Evaluate(Request{ClientID: "c"})
	if res.Effect != domain.EffectPermit || len(res.ReplyAttributes) != 1 {
		t.Fatalf("%+v", res)
	}
	got := res.ReplyAttributes[0]
	if got.Key.Vendor != 9 || got.Key.Code != 1 || string(got.Raw) != "foo" {
		t.Fatalf("vsa=%+v", got)
	}
}

func TestCompileMissingFallback(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{FallbackID: "missing"})
	if err == nil {
		t.Fatal("expected missing fallback")
	}
	de, _ := domain.AsError(err)
	if de.Code != domain.CodeNotFound {
		t.Fatalf("got %v", err)
	}
}

func intAttr(name string, code uint8, v uint32) Typed {
	return Typed{Key: AttrKey{Name: name, Code: code}, Kind: KindInteger, Uint: v}
}

func textAttr(name string, code uint8, v string) Typed {
	return Typed{Key: AttrKey{Name: name, Code: code}, Kind: KindText, Text: v}
}

func mustCompile(t testing.TB, in Input) *Engine {
	t.Helper()
	eng, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}
