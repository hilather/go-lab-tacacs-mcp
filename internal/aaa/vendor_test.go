package aaa

import (
	"os"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/policy"
	"gopkg.in/yaml.v3"
)

type vendorCatalog struct {
	Fixtures []vendorFixture `yaml:"fixtures"`
}

type vendorFixture struct {
	ID        string       `yaml:"id"`
	Vendor    string       `yaml:"vendor"`
	Kind      string       `yaml:"kind"`
	Notes     string       `yaml:"notes"`
	User      string       `yaml:"user"`
	Client    string       `yaml:"client"`
	Arguments []fixtureAV  `yaml:"arguments"`
	Expect    vendorExpect `yaml:"expect"`
}

type fixtureAV struct {
	Name      string `yaml:"name"`
	Separator string `yaml:"separator"`
	Value     string `yaml:"value"`
}

type vendorExpect struct {
	Evaluator       string      `yaml:"evaluator"`
	Decision        string      `yaml:"decision"`
	Status          string      `yaml:"status"`
	Arguments       []fixtureAV `yaml:"arguments"`
	WinnerRule      string      `yaml:"winner_rule"`
	PreserveCmdArgs []string    `yaml:"preserve_cmd_args"`
}

func TestVendorFixturesThroughEvaluators(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(testdata(t, "vendors", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.CompileDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	fxRaw, err := os.ReadFile(testdata(t, "vendors", "fixtures.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cat vendorCatalog
	if err := yaml.Unmarshal(fxRaw, &cat); err != nil {
		t.Fatal(err)
	}
	if len(cat.Fixtures) == 0 {
		t.Fatal("no vendor fixtures")
	}
	for _, fx := range cat.Fixtures {
		fx := fx
		t.Run(fx.ID, func(t *testing.T) {
			t.Parallel()
			req := AuthorizationRequest{
				UserID:    fx.User,
				ClientID:  fx.Client,
				Arguments: fixtureAVs(fx.Arguments),
			}
			tr, res, err := Evaluate(eng, req)
			if err != nil {
				t.Fatal(err)
			}
			if tr.Evaluator != fx.Expect.Evaluator {
				t.Fatalf("evaluator=%s want %s", tr.Evaluator, fx.Expect.Evaluator)
			}
			if res.Decision.String() != fx.Expect.Decision || res.Status.String() != fx.Expect.Status {
				t.Fatalf("decision=%s/%s want %s/%s", res.Decision, res.Status, fx.Expect.Decision, fx.Expect.Status)
			}
			want := fixtureAVs(fx.Expect.Arguments)
			if !res.Arguments.Equal(want) {
				t.Fatalf("reply AVs got %+v want %+v", res.Arguments, want)
			}
			if fx.Expect.WinnerRule != "" {
				if tr.Winner == nil || tr.Winner.RuleID != fx.Expect.WinnerRule {
					t.Fatalf("winner=%+v want %s", tr.Winner, fx.Expect.WinnerRule)
				}
			}
			if tr.Evaluator == string(domain.RuleKindCommand) {
				for _, st := range tr.Steps {
					if st.Kind == string(domain.RuleKindService) {
						t.Fatalf("command walk consulted a service rule: %+v", st)
					}
				}
			}
			for i, a := range fx.Arguments {
				got := tr.RequestArguments[i]
				if got.Name != a.Name || got.Value != a.Value {
					t.Fatalf("request AV[%d] not preserved: %+v", i, got)
				}
			}
			if len(fx.Expect.PreserveCmdArgs) > 0 && !reflectStrings(tr.CmdArgs, fx.Expect.PreserveCmdArgs) {
				t.Fatalf("cmd-arg order=%v want %v", tr.CmdArgs, fx.Expect.PreserveCmdArgs)
			}
			if fx.Vendor == "" {
				t.Fatal("fixture missing vendor provenance")
			}
		})
	}
}

func fixtureAVs(in []fixtureAV) domain.AVPairs {
	out := make(domain.AVPairs, 0, len(in))
	for _, a := range in {
		sep := domain.AVSepMandatory
		if a.Separator != "" {
			sep = a.Separator[0]
		}
		out = append(out, domain.AVPair{Name: a.Name, Separator: sep, Value: a.Value})
	}
	return out
}

func reflectStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
