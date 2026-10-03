package state

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestBaselineHashCoversPolicyConfiguration(t *testing.T) {
	cases := []struct {
		name string
		edit func(*config.Document)
	}{
		{"group enabled", func(d *config.Document) { d.Groups[0].Enabled = false }},
		{"group priority", func(d *config.Document) { d.Groups[0].Priority++ }},
		{"command rule", func(d *config.Document) { d.Groups[0].CommandRules[0].Command.Exact = "configure" }},
		{"client match", func(d *config.Document) { d.Clients[0].Match.SourceCIDRs = []string{"192.0.2.0/24"} }},
		{"client priority", func(d *config.Document) { d.Clients[0].Priority++ }},
		{"user membership", func(d *config.Document) { d.Users[0].GroupIDs = nil }},
		{"fallback rules", func(d *config.Document) {
			d.FallbackRules = d.Users[0].Rules
			d.FallbackRules.CommandRules = []config.CommandRule{{ID: "fallback", Action: domain.DecisionDeny}}
		}},
		{"token scopes", func(d *config.Document) {
			d.API.BootstrapTokens = []config.BootstrapToken{{ID: "admin", Scopes: []string{"state:read"}}}
		}},
		{"limits", func(d *config.Document) { d.Limits.MaxUsernameBytes++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParse(t, smallYAML)
			before, err := hashBaseline(doc)
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(doc)
			after, err := hashBaseline(doc)
			if err != nil {
				t.Fatal(err)
			}
			if after == before {
				t.Fatal("changed configuration retained baseline hash")
			}
		})
	}
}
func TestOverlayHashCoversAdministrativeChanges(t *testing.T) {
	m := mustMgr(t, smallYAML)
	one, err := m.UpdateGroup("ops", UpdateGroup{Priority: intPtr(11)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := m.UpdateGroup("ops", UpdateGroup{Priority: intPtr(12)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if one.OverlayHash == two.OverlayHash {
		t.Fatal("priority change retained overlay hash")
	}
	disabled, err := m.UpdateGroup("ops", UpdateGroup{Enabled: boolPtr(false)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.OverlayHash == two.OverlayHash {
		t.Fatal("group enable change retained overlay hash")
	}
	clientOne, err := m.UpdateClient("sw", UpdateClient{Priority: intPtr(101)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientTwo, err := m.UpdateClient("sw", UpdateClient{Priority: intPtr(102)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if clientOne.OverlayHash == clientTwo.OverlayHash {
		t.Fatal("client priority retained overlay hash")
	}
	first, err := m.CreateToken(CreateToken{ID: "rt", Scopes: []string{"state:read"}, Material: credentials.NewTokenMaterial([]byte("first-token"))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.CreateToken(CreateToken{ID: "rt", Scopes: []string{"tokens:manage"}, Material: credentials.NewTokenMaterial([]byte("second-token")), Override: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.OverlayHash == second.OverlayHash {
		t.Fatal("token grant change retained overlay hash")
	}
}

func TestBaselineHashCoversRADIUSMatchesAndReplies(t *testing.T) {
	doc := mustParse(t, smallYAML)
	doc.RADIUSPolicies = []config.RADIUSPolicy{{ID: "radius", Rules: []config.RADIUSRule{{ID: "rule", Enabled: true, Effect: domain.EffectPermit, Match: config.RADIUSMatch{Attributes: []config.RADIUSAttrMatch{{Name: "NAS-Identifier", Op: "exact", Value: "lab-one"}}}}}}}
	doc.RADIUSReplyProfiles = []config.RADIUSReplyProfile{{ID: "reply", Attributes: []config.RADIUSReplyAttr{{Name: "Reply-Message", Value: "first"}}}}
	before, err := hashBaseline(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.RADIUSPolicies[0].Rules[0].Match.Attributes[0].Value = "lab-two"
	matched, err := hashBaseline(doc)
	if err != nil {
		t.Fatal(err)
	}
	if matched == before {
		t.Fatal("RADIUS match retained hash")
	}
	doc.RADIUSReplyProfiles[0].Attributes[0].Value = "second"
	replied, err := hashBaseline(doc)
	if err != nil {
		t.Fatal(err)
	}
	if replied == matched {
		t.Fatal("RADIUS reply attribute retained hash")
	}
}

func TestBaselineHashIgnoresIdentityCollectionAndMapInsertionOrder(t *testing.T) {
	doc := mustParse(t, smallYAML)
	doc.Users = append(doc.Users, config.User{ID: "second", Labels: map[string]string{"a": "one", "b": "two"}})
	before, err := hashBaseline(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.Users[0], doc.Users[1] = doc.Users[1], doc.Users[0]
	doc.Users[0].Labels = map[string]string{"b": "two", "a": "one"}
	after, err := hashBaseline(doc)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("identity order changed configuration identity")
	}
}

func TestOverlayHashSecretContributionIsProcessKeyed(t *testing.T) {
	ov := newOverlay()
	ov.secrets["login:alice"] = []byte("verifier-canary")
	one, err := hashOverlay(ov, []byte("process-key-one"))
	if err != nil {
		t.Fatal(err)
	}
	same, err := hashOverlay(ov, []byte("process-key-one"))
	if err != nil {
		t.Fatal(err)
	}
	different, err := hashOverlay(ov, []byte("process-key-two"))
	if err != nil {
		t.Fatal(err)
	}
	if one != same || one == different {
		t.Fatal("secret contribution was not deterministic and process keyed")
	}
	ov.secrets["login:alice"] = []byte("replacement-verifier")
	changed, err := hashOverlay(ov, []byte("process-key-one"))
	if err != nil {
		t.Fatal(err)
	}
	if changed == one {
		t.Fatal("verifier replacement retained overlay hash")
	}
}

func BenchmarkStateFingerprints(b *testing.B) {
	doc := benchDocument(50, 200, 20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := hashBaseline(doc); err != nil {
			b.Fatal(err)
		}
	}
}

func TestBaselineHashCoversExistingTokenScopes(t *testing.T) {
	doc := mustParse(t, smallYAML)
	doc.API.BootstrapTokens = []config.BootstrapToken{{ID: "admin", Scopes: []string{"state:read"}}}
	before, err := hashBaseline(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.API.BootstrapTokens[0].Scopes = []string{"tokens:manage"}
	after, err := hashBaseline(doc)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("existing token scope change retained hash")
	}
}
