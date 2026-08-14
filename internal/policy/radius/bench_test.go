package radius

import (
	"fmt"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func benchEngine(n int) *Engine {
	rules := make([]config.RADIUSRule, 0, n+1)
	for i := 0; i < n; i++ {
		rules = append(rules, config.RADIUSRule{
			ID:      fmt.Sprintf("miss-%05d", i),
			Enabled: true,
			Match:   config.RADIUSMatch{GroupsAny: []string{fmt.Sprintf("g-%d", i)}},
			Effect:  domain.EffectPermit,
		})
	}
	rules = append(rules, config.RADIUSRule{ID: "deny", Enabled: true, Effect: domain.EffectDeny})
	eng, err := Compile(Input{
		Policies: []config.RADIUSPolicy{{ID: "p", Rules: rules}},
		Clients: []config.Client{{
			ID:        "c",
			Enabled:   true,
			Endpoints: []config.ClientEndpoint{{ID: "e", Protocol: domain.ProtocolRADIUS, RADIUS: &config.RADIUSEndpoint{AccessPolicyID: "p"}}},
		}},
	})
	if err != nil {
		panic(err)
	}
	return eng
}

func BenchmarkRadiusPolicyEvaluate(b *testing.B) {
	eng := benchEngine(64)
	req := Request{ClientID: "c", EndpointID: "e", Method: domain.AuthMethodPassword, Groups: []string{"none"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := eng.Evaluate(req)
		if res.Effect != domain.EffectDeny {
			b.Fatalf("effect=%s", res.Effect)
		}
	}
}

func BenchmarkRadiusPolicyCompile(b *testing.B) {
	in := Input{
		Policies: []config.RADIUSPolicy{{
			ID: "p",
			Rules: []config.RADIUSRule{
				{ID: "a", Enabled: true, Match: config.RADIUSMatch{GroupsAny: []string{"g"}}, Effect: domain.EffectPermit},
				{ID: "b", Enabled: true, Effect: domain.EffectDeny},
			},
		}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(in); err != nil {
			b.Fatal(err)
		}
	}
}
