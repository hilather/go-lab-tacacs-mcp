package policy

import (
	"fmt"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func benchInput(rules int, regex bool) Input {
	cmds := make([]config.CommandRule, 0, rules)
	for i := 0; i < rules; i++ {
		r := config.CommandRule{
			ID:       fmt.Sprintf("r-%05d", i),
			Priority: i,
			Action:   domain.DecisionDeny,
		}
		if regex {
			r.Command = config.StringMatch{Pattern: fmt.Sprintf("^bench-miss-%d-.*$", i)}
			r.Arguments = config.StringMatch{Pattern: ".*"}
		} else {
			r.Command = config.StringMatch{Exact: fmt.Sprintf("miss-%d", i)}
			r.Arguments = config.StringMatch{Exact: ""}
		}
		cmds = append(cmds, r)
	}
	last := config.CommandRule{
		ID:        "hit",
		Priority:  rules + 1,
		Action:    domain.DecisionPermitAdd,
		Command:   config.StringMatch{Exact: "show"},
		Arguments: config.StringMatch{Pattern: ".*"},
	}
	if regex {
		last.Command = config.StringMatch{Pattern: "^show$"}
	}
	cmds = append(cmds, last)
	return Input{
		Groups: []config.Group{{
			ID:           "g",
			Enabled:      true,
			CommandRules: cmds,
		}},
		Users: []config.User{{
			ID:       "u",
			Enabled:  true,
			GroupIDs: []string{"g"},
		}},
	}
}

func BenchmarkPolicyCompile_Small(b *testing.B) {
	in := benchInput(100, true)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPolicyCompile_Medium(b *testing.B) {
	in := benchInput(5000, true)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthorize_ExactCommand(b *testing.B) {
	eng, err := Compile(benchInput(100, false))
	if err != nil {
		b.Fatal(err)
	}
	req := cmdReq("u", "", "show", "version")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := eng.Authorize(req)
		if res.Decision != domain.DecisionPermitAdd {
			b.Fatalf("decision=%s", res.Decision)
		}
	}
}

func BenchmarkAuthorize_RegexWorstCase(b *testing.B) {
	eng, err := Compile(benchInput(5000, true))
	if err != nil {
		b.Fatal(err)
	}
	req := cmdReq("u", "", "show", "running-config")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := eng.Authorize(req)
		if res.Decision != domain.DecisionPermitAdd {
			b.Fatalf("decision=%s", res.Decision)
		}
	}
}

func BenchmarkAuthorize_ServiceSession(b *testing.B) {
	eng := mustCompileFile(b, "policies", "personas.yaml")
	req := sessionReq("lab-admin", "lab-switches")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := eng.Authorize(req)
		if res.Decision != domain.DecisionPermitAdd {
			b.Fatalf("decision=%s", res.Decision)
		}
	}
}
