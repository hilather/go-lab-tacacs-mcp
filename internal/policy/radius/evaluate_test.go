package radius

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func personaEngine(t testing.TB) *Engine {
	t.Helper()
	pw := domain.AuthMethodPassword
	return mustCompile(t, Input{
		ReplyProfiles: []config.RADIUSReplyProfile{
			{ID: "lab-accept", Attributes: []config.RADIUSReplyAttr{{Name: "Session-Timeout", Value: "600"}}},
			{ID: "reject-msg", Attributes: []config.RADIUSReplyAttr{{Name: "Reply-Message", Value: "denied"}}},
		},
		Policies: []config.RADIUSPolicy{
			{
				ID: "default-radius-access",
				Rules: []config.RADIUSRule{
					{
						ID:            "permit-lab-admins",
						Enabled:       true,
						Match:         config.RADIUSMatch{GroupsAny: []string{"lab-admins"}},
						Effect:        domain.EffectPermit,
						ReplyProfiles: []string{"lab-accept"},
					},
					{
						ID:      "permit-pap-nas",
						Enabled: true,
						Match: config.RADIUSMatch{
							Method: &pw,
							Attributes: []config.RADIUSAttrMatch{
								{Name: "NAS-Identifier", Op: config.RADIUSMatchOpEquals, Value: "edge-1"},
								{Name: "Service-Type", Op: config.RADIUSMatchOpPresent},
								{Name: "Calling-Station-Id", Op: config.RADIUSMatchOpAbsent},
							},
						},
						Effect:        domain.EffectPermit,
						ReplyProfiles: []string{"lab-accept"},
					},
					{
						ID:            "deny-rest",
						Enabled:       true,
						Effect:        domain.EffectDeny,
						ReplyProfiles: []string{"reject-msg"},
					},
				},
			},
			{
				ID: "fallback-permit",
				Rules: []config.RADIUSRule{{
					ID:      "permit-all",
					Enabled: true,
					Effect:  domain.EffectPermit,
				}},
			},
		},
		FallbackID: "",
		Clients: []config.Client{{
			ID:      "lab-switches",
			Enabled: true,
			Endpoints: []config.ClientEndpoint{{
				ID:       "radius-udp",
				Protocol: domain.ProtocolRADIUS,
				RADIUS:   &config.RADIUSEndpoint{AccessPolicyID: "default-radius-access"},
			}},
		}},
	})
}

func TestEvaluateGroupsAnyPermit(t *testing.T) {
	t.Parallel()
	eng := personaEngine(t)
	res := eng.Evaluate(Request{
		UserID:     "lab-admin",
		ClientID:   "lab-switches",
		EndpointID: "radius-udp",
		Method:     domain.AuthMethodPassword,
		Groups:     []string{"lab-admins"},
	})
	if res.Effect != domain.EffectPermit {
		t.Fatalf("effect=%s", res.Effect)
	}
	if res.Trace.Winner == nil || res.Trace.Winner.Source != "client_policy:default-radius-access" {
		t.Fatalf("winner=%+v", res.Trace.Winner)
	}
	if len(res.ReplyAttributes) != 1 || res.ReplyAttributes[0].Uint != 600 {
		t.Fatalf("reply=%+v", res.ReplyAttributes)
	}
}

func TestEvaluateDefaultDenyUnknownClient(t *testing.T) {
	t.Parallel()
	eng := personaEngine(t)
	res := eng.Evaluate(Request{UserID: "x", ClientID: "unknown", Method: domain.AuthMethodPassword})
	if res.Effect != domain.EffectDeny || res.Trace.Winner != nil {
		t.Fatalf("%+v", res)
	}
	if res.Trace.DefaultDeny != "no matching access rule" {
		t.Fatalf("deny=%q", res.Trace.DefaultDeny)
	}
}

func TestEvaluateClientDenyBeforeFallback(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{
		Policies: []config.RADIUSPolicy{
			{ID: "client", Rules: []config.RADIUSRule{{ID: "deny", Enabled: true, Effect: domain.EffectDeny}}},
			{ID: "fb", Rules: []config.RADIUSRule{{ID: "permit", Enabled: true, Effect: domain.EffectPermit}}},
		},
		FallbackID: "fb",
		Clients: []config.Client{{
			ID:        "c",
			Enabled:   true,
			Endpoints: []config.ClientEndpoint{{ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "client"}}},
		}},
	})
	res := eng.Evaluate(Request{ClientID: "c", EndpointID: "e"})
	if res.Effect != domain.EffectDeny || res.Trace.Winner.RuleID != "deny" {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateFallbackWhenClientMisses(t *testing.T) {
	t.Parallel()
	chap := domain.AuthMethodCHAP
	eng := mustCompile(t, Input{
		Policies: []config.RADIUSPolicy{
			{ID: "client", Rules: []config.RADIUSRule{{
				ID:      "only-chap",
				Enabled: true,
				Match:   config.RADIUSMatch{Method: &chap},
				Effect:  domain.EffectPermit,
			}}},
			{ID: "fb", Rules: []config.RADIUSRule{{ID: "permit", Enabled: true, Effect: domain.EffectPermit}}},
		},
		FallbackID: "fb",
		Clients: []config.Client{{
			ID:        "c",
			Enabled:   true,
			Endpoints: []config.ClientEndpoint{{ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "client"}}},
		}},
	})
	res := eng.Evaluate(Request{ClientID: "c", Method: domain.AuthMethodPassword})
	if res.Effect != domain.EffectPermit || res.Trace.Winner.Source != sourceFallback {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateAttributeOperators(t *testing.T) {
	t.Parallel()
	eng := personaEngine(t)
	req := Request{
		ClientID:   "lab-switches",
		EndpointID: "radius-udp",
		Method:     domain.AuthMethodPassword,
		Attributes: TypedSet{
			textAttr("NAS-Identifier", 32, "edge-1"),
			intAttr("Service-Type", 6, 1),
			intAttr("Service-Type", 6, 2), // extra instance ignored for equals/present
		},
	}
	res := eng.Evaluate(req)
	if res.Effect != domain.EffectPermit || res.Trace.Winner.RuleID != "permit-pap-nas" {
		t.Fatalf("%+v", res)
	}
	req.Attributes = TypedSet{
		textAttr("NAS-Identifier", 32, "edge-2"),
		intAttr("Service-Type", 6, 1),
	}
	res = eng.Evaluate(req)
	if res.Effect != domain.EffectDeny || res.Trace.Winner.RuleID != "deny-rest" {
		t.Fatalf("wrong nas: %+v", res)
	}
	req.Attributes = TypedSet{textAttr("NAS-Identifier", 32, "edge-1")}
	res = eng.Evaluate(req)
	if res.Effect != domain.EffectDeny {
		t.Fatalf("missing Service-Type should not match present: %+v", res)
	}
	req.Attributes = TypedSet{
		textAttr("NAS-Identifier", 32, "edge-1"),
		intAttr("Service-Type", 6, 1),
		textAttr("Calling-Station-Id", 31, "aa:bb"),
	}
	res = eng.Evaluate(req)
	if res.Effect != domain.EffectDeny {
		t.Fatalf("Calling-Station-Id present should fail absent: %+v", res)
	}
}

func TestEvaluateNilEngineIsError(t *testing.T) {
	t.Parallel()
	var eng *Engine
	res := eng.Evaluate(Request{})
	if res.Effect != domain.EffectError {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateNoUserGroupRules(t *testing.T) {
	t.Parallel()
	// Groups are only a match predicate. There is no users[].radius_policy_id.
	eng := personaEngine(t)
	res := eng.Evaluate(Request{
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Method:   domain.AuthMethodPassword,
		Groups:   nil,
	})
	if res.Effect != domain.EffectDeny || res.Trace.Winner == nil || res.Trace.Winner.RuleID != "deny-rest" {
		t.Fatalf("without groups_any membership, catch-all deny: %+v", res)
	}
}

func TestCheckReplyLegalAcceptAndRejectRoles(t *testing.T) {
	t.Parallel()
	timeout := Typed{Key: AttrKey{Name: "Session-Timeout", Code: 27}, Kind: KindInteger, Uint: 600}
	msg := Typed{Key: AttrKey{Name: "Reply-Message", Code: 18}, Kind: KindText, Text: "denied"}
	nas := Typed{Key: AttrKey{Name: "NAS-IP-Address", Code: 4}, Kind: KindIPv4}
	vsa := Typed{Key: AttrKey{Vendor: 9, Code: 1, Name: "Vendor-Specific"}, Kind: KindVSA, Raw: []byte("foo")}
	if err := CheckReplyLegal(domain.EffectPermit, TypedSet{timeout, msg, vsa}); err != nil {
		t.Fatalf("legal accept: %v", err)
	}
	if err := CheckReplyLegal(domain.EffectDeny, TypedSet{msg}); err != nil {
		t.Fatalf("legal reject: %v", err)
	}
	if err := CheckReplyLegal(domain.EffectPermit, TypedSet{nas}); err == nil {
		t.Fatal("NAS-IP-Address is not legal on Access-Accept")
	}
	if err := CheckReplyLegal(domain.EffectDeny, TypedSet{timeout}); err == nil {
		t.Fatal("Session-Timeout is not legal on Access-Reject")
	}
	if err := CheckReplyLegal(domain.EffectDeny, TypedSet{vsa}); err == nil {
		t.Fatal("raw VSA is not legal on Access-Reject")
	}
}

func TestEvaluateIllegalReplyIsError(t *testing.T) {
	t.Parallel()
	eng := &Engine{
		policies: map[string]compiledPolicy{
			"p": {id: "p", rules: []compiledRule{{
				id:     "bad",
				effect: domain.EffectPermit,
				reply:  TypedSet{{Key: AttrKey{Name: "NAS-IP-Address", Code: 4}, Kind: KindIPv4}},
			}}},
		},
		clients: map[string]compiledClient{"c": {endpointID: "e", policyID: "p"}},
	}
	res := eng.Evaluate(Request{ClientID: "c", EndpointID: "e"})
	if res.Effect != domain.EffectError || res.Trace.Error == "" {
		t.Fatalf("illegal compiled reply must fail closed: %+v", res)
	}
	if len(res.ReplyAttributes) != 0 {
		t.Fatalf("error must not emit reply attrs: %+v", res.ReplyAttributes)
	}
}
