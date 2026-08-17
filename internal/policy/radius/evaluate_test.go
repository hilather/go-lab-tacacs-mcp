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

func TestEvaluateNoUserGroupAttachmentFallsThrough(t *testing.T) {
	t.Parallel()
	// Unattached users still use client policy. groups_any is a match predicate.
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

func userGroupEngine(t testing.TB) *Engine {
	t.Helper()
	chap := domain.AuthMethodCHAP
	return mustCompile(t, Input{
		ReplyProfiles: []config.RADIUSReplyProfile{
			{ID: "user-accept", Attributes: []config.RADIUSReplyAttr{{Name: "Session-Timeout", Value: "100"}}},
			{ID: "group-accept", Attributes: []config.RADIUSReplyAttr{{Name: "Session-Timeout", Value: "200"}}},
			{ID: "client-msg", Attributes: []config.RADIUSReplyAttr{{Name: "Reply-Message", Value: "client"}}},
		},
		Policies: []config.RADIUSPolicy{
			{ID: "user-permit", Rules: []config.RADIUSRule{{
				ID: "permit-user", Enabled: true, Effect: domain.EffectPermit, ReplyProfiles: []string{"user-accept"},
			}}},
			{ID: "user-chap-only", Rules: []config.RADIUSRule{{
				ID: "only-chap", Enabled: true, Match: config.RADIUSMatch{Method: &chap}, Effect: domain.EffectPermit,
			}}},
			{ID: "admins-permit", Rules: []config.RADIUSRule{{
				ID: "permit-admins", Enabled: true, Effect: domain.EffectPermit, ReplyProfiles: []string{"group-accept"},
			}}},
			{ID: "ops-permit", Rules: []config.RADIUSRule{{
				ID: "permit-ops", Enabled: true, Effect: domain.EffectPermit,
			}}},
			{ID: "client-deny", Rules: []config.RADIUSRule{{
				ID: "deny-client", Enabled: true, Effect: domain.EffectDeny, ReplyProfiles: []string{"client-msg"},
			}}},
			{ID: "fallback-permit", Rules: []config.RADIUSRule{{
				ID: "permit-fallback", Enabled: true, Effect: domain.EffectPermit,
			}}},
		},
		FallbackID: "fallback-permit",
		Clients: []config.Client{
			{
				ID:      "lab-switches",
				Enabled: true,
				Endpoints: []config.ClientEndpoint{{
					ID: "radius-udp", Protocol: domain.ProtocolRADIUS,
					RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "client-deny"},
				}},
			},
			{
				ID:            "lab-defaults",
				Enabled:       true,
				Authorization: config.ClientAuthz{DefaultGroupIDs: []string{"ops"}},
				Endpoints: []config.ClientEndpoint{{
					ID: "radius-udp", Protocol: domain.ProtocolRADIUS,
					RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "client-deny"},
				}},
			},
		},
		Groups: []config.Group{
			{ID: "admins", Enabled: true, Priority: 20, RADIUSPolicyID: "admins-permit"},
			{ID: "ops", Enabled: true, Priority: 10, RADIUSPolicyID: "ops-permit"},
			{ID: "disabled-g", Enabled: false, Priority: 1, RADIUSPolicyID: "admins-permit"},
			{ID: "plain", Enabled: true, Priority: 5},
		},
		Users: []config.User{
			{ID: "attached", Enabled: true, GroupIDs: []string{"admins"}, RADIUSPolicyID: "user-permit"},
			{ID: "chap-user", Enabled: true, GroupIDs: []string{"admins"}, RADIUSPolicyID: "user-chap-only"},
			{ID: "grouped", Enabled: true, GroupIDs: []string{"admins", "plain"}},
			{ID: "priority", Enabled: true, GroupIDs: []string{"admins", "ops"}},
			{ID: "disabled-u", Enabled: false, GroupIDs: []string{"admins"}, RADIUSPolicyID: "user-permit"},
			{ID: "bare", Enabled: true},
		},
	})
}

func TestEvaluateUserPolicyBeforeGroupAndClient(t *testing.T) {
	t.Parallel()
	eng := userGroupEngine(t)
	res := eng.Evaluate(Request{UserID: "attached", ClientID: "lab-switches", EndpointID: "radius-udp"})
	if res.Effect != domain.EffectPermit || res.Trace.Winner == nil {
		t.Fatalf("%+v", res)
	}
	if res.Trace.Winner.Source != sourceUserPrefix+"user-permit" || res.Trace.Winner.RuleID != "permit-user" {
		t.Fatalf("winner=%+v", res.Trace.Winner)
	}
	if len(res.ReplyAttributes) != 1 || res.ReplyAttributes[0].Uint != 100 {
		t.Fatalf("reply=%+v", res.ReplyAttributes)
	}
}

func TestEvaluateUserPolicyMissFallsToGroup(t *testing.T) {
	t.Parallel()
	eng := userGroupEngine(t)
	res := eng.Evaluate(Request{
		UserID: "chap-user", ClientID: "lab-switches", EndpointID: "radius-udp",
		Method: domain.AuthMethodPassword,
	})
	if res.Effect != domain.EffectPermit || res.Trace.Winner == nil || res.Trace.Winner.Source != sourceGroupPrefix+"admins-permit" {
		t.Fatalf("expected admins group after user miss: %+v", res)
	}
	if len(res.Trace.Steps) < 2 || res.Trace.Steps[0].Source != sourceUserPrefix+"user-chap-only" || res.Trace.Steps[0].Matched {
		t.Fatalf("steps=%+v", res.Trace.Steps)
	}
}

func TestEvaluateGroupPolicyBeforeClient(t *testing.T) {
	t.Parallel()
	eng := userGroupEngine(t)
	res := eng.Evaluate(Request{UserID: "grouped", ClientID: "lab-switches", EndpointID: "radius-udp"})
	if res.Effect != domain.EffectPermit || res.Trace.Winner == nil || res.Trace.Winner.Source != sourceGroupPrefix+"admins-permit" {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateGroupPriorityThenID(t *testing.T) {
	t.Parallel()
	eng := userGroupEngine(t)
	res := eng.Evaluate(Request{UserID: "priority", ClientID: "lab-switches", EndpointID: "radius-udp"})
	// ops priority 10 before admins priority 20
	if res.Trace.Winner == nil || res.Trace.Winner.Source != sourceGroupPrefix+"ops-permit" {
		t.Fatalf("lower priority number wins: %+v", res)
	}
}

func TestEvaluateEqualGroupPrioritySortsByID(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{
		Policies: []config.RADIUSPolicy{
			{ID: "a-pol", Rules: []config.RADIUSRule{{ID: "a", Enabled: true, Effect: domain.EffectPermit}}},
			{ID: "b-pol", Rules: []config.RADIUSRule{{ID: "b", Enabled: true, Effect: domain.EffectDeny}}},
		},
		Groups: []config.Group{
			{ID: "zeta", Enabled: true, Priority: 5, RADIUSPolicyID: "b-pol"},
			{ID: "alpha", Enabled: true, Priority: 5, RADIUSPolicyID: "a-pol"},
		},
		Users: []config.User{{ID: "u", Enabled: true, GroupIDs: []string{"zeta", "alpha"}}},
	})
	res := eng.Evaluate(Request{UserID: "u"})
	if res.Trace.Winner == nil || res.Trace.Winner.Source != sourceGroupPrefix+"a-pol" {
		t.Fatalf("equal priority sorts by id: %+v", res)
	}
}

func TestEvaluateDisabledUserSkipsUserPolicy(t *testing.T) {
	t.Parallel()
	eng := userGroupEngine(t)
	// lab-switches has no default_group_ids, so only user policy/groups are skipped.
	res := eng.Evaluate(Request{UserID: "disabled-u", ClientID: "lab-switches", EndpointID: "radius-udp"})
	if res.Trace.Winner == nil || res.Trace.Winner.Source != sourceClientPrefix+"client-deny" {
		t.Fatalf("disabled user without client defaults hits client policy: %+v", res)
	}
}

func TestEvaluateDisabledUserStillGetsClientDefaultGroups(t *testing.T) {
	t.Parallel()
	eng := userGroupEngine(t)
	res := eng.Evaluate(Request{
		UserID:     "disabled-u",
		ClientID:   "lab-defaults",
		EndpointID: "radius-udp",
		// Caller Groups must not win: compiled user uses effectiveGroups.
		Groups: []string{"admins"},
	})
	if res.Trace.Winner == nil || res.Trace.Winner.Source != sourceGroupPrefix+"ops-permit" {
		t.Fatalf("disabled user still walks client default groups: %+v", res)
	}
	if len(res.Trace.Groups) != 1 || res.Trace.Groups[0] != "ops" {
		t.Fatalf("groups_any membership must be client defaults only: %v", res.Trace.Groups)
	}
}

func TestEvaluateDisabledUserGroupsAnyUsesClientDefaults(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{
		Policies: []config.RADIUSPolicy{
			{ID: "ops-any", Rules: []config.RADIUSRule{{
				ID: "need-ops", Enabled: true,
				Match:  config.RADIUSMatch{GroupsAny: []string{"ops"}},
				Effect: domain.EffectPermit,
			}}},
			{ID: "client", Rules: []config.RADIUSRule{{ID: "deny", Enabled: true, Effect: domain.EffectDeny}}},
		},
		Clients: []config.Client{{
			ID:            "c",
			Enabled:       true,
			Authorization: config.ClientAuthz{DefaultGroupIDs: []string{"ops"}},
			Endpoints: []config.ClientEndpoint{{
				ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "client"},
			}},
		}},
		Groups: []config.Group{{ID: "ops", Enabled: true, Priority: 10, RADIUSPolicyID: "ops-any"}},
		Users: []config.User{
			{ID: "off", Enabled: false, GroupIDs: []string{"ops"}, RADIUSPolicyID: "ops-any"},
		},
	})
	res := eng.Evaluate(Request{UserID: "off", ClientID: "c", EndpointID: "e"})
	if res.Effect != domain.EffectPermit || res.Trace.Winner == nil || res.Trace.Winner.RuleID != "need-ops" {
		t.Fatalf("groups_any must see client default membership: %+v", res)
	}
}

func TestEvaluateDisabledGroupSkipped(t *testing.T) {
	t.Parallel()
	eng := mustCompile(t, Input{
		Policies: []config.RADIUSPolicy{
			{ID: "off", Rules: []config.RADIUSRule{{ID: "off-rule", Enabled: true, Effect: domain.EffectPermit}}},
			{ID: "client", Rules: []config.RADIUSRule{{ID: "c", Enabled: true, Effect: domain.EffectDeny}}},
		},
		Clients: []config.Client{{
			ID: "c", Enabled: true,
			Endpoints: []config.ClientEndpoint{{
				ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "client"},
			}},
		}},
		Groups: []config.Group{{ID: "g", Enabled: false, RADIUSPolicyID: "off"}},
		Users:  []config.User{{ID: "u", Enabled: true, GroupIDs: []string{"g"}}},
	})
	res := eng.Evaluate(Request{UserID: "u", ClientID: "c", EndpointID: "e"})
	if res.Trace.Winner == nil || res.Trace.Winner.Source != sourceClientPrefix+"client" {
		t.Fatalf("disabled group skipped: %+v", res)
	}
}

func TestEvaluateClientDefaultGroups(t *testing.T) {
	t.Parallel()
	eng := userGroupEngine(t)
	res := eng.Evaluate(Request{UserID: "bare", ClientID: "lab-defaults", EndpointID: "radius-udp"})
	if res.Trace.Winner == nil || res.Trace.Winner.Source != sourceGroupPrefix+"ops-permit" {
		t.Fatalf("client default group: %+v", res)
	}
}

func TestEvaluateMissingUserGroupPolicyIsError(t *testing.T) {
	t.Parallel()
	eng := &Engine{
		policies: map[string]compiledPolicy{},
		users:    map[string]compiledUser{"u": {id: "u", enabled: true, policyID: "gone"}},
	}
	res := eng.Evaluate(Request{UserID: "u"})
	if res.Effect != domain.EffectError || res.Trace.Error == "" {
		t.Fatalf("missing compiled policy must fail closed: %+v", res)
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
