package policy

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestPersonasSessionVersusCommand(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")

	adminSess := eng.Authorize(sessionReq("lab-admin", "lab-switches"))
	if adminSess.Decision != domain.DecisionPermitAdd || adminSess.Status != domain.AuthorStatusPassAdd {
		t.Fatalf("admin session: %+v", adminSess)
	}
	if !adminSess.Arguments.Equal(domain.AVPairs{av("priv-lvl", '=', "15")}) {
		t.Fatalf("admin session AVs: %+v", adminSess.Arguments)
	}
	if adminSess.Trace.Winner == nil || adminSess.Trace.Winner.Source != "group:administrators" {
		t.Fatalf("admin session winner: %+v", adminSess.Trace.Winner)
	}
	if adminSess.Trace.Evaluator != "service" {
		t.Fatalf("admin session evaluator=%q", adminSess.Trace.Evaluator)
	}

	adminCmd := eng.Authorize(cmdReq("lab-admin", "lab-switches", "configure"))
	if adminCmd.Decision != domain.DecisionPermitAdd {
		t.Fatalf("admin configure: %+v", adminCmd)
	}
	if adminCmd.Trace.Winner == nil || adminCmd.Trace.Winner.RuleID != "permit-all" {
		t.Fatalf("admin configure winner: %+v", adminCmd.Trace.Winner)
	}
	if adminCmd.Trace.Evaluator != "command" {
		t.Fatalf("admin configure evaluator=%q", adminCmd.Trace.Evaluator)
	}

	roSess := eng.Authorize(sessionReq("lab-readonly", "lab-switches"))
	if roSess.Decision != domain.DecisionPermitAdd || !roSess.Arguments.Equal(domain.AVPairs{av("priv-lvl", '=', "1")}) {
		t.Fatalf("readonly session: %+v", roSess)
	}

	roCmd := eng.Authorize(cmdReq("lab-readonly", "lab-switches", "configure"))
	if roCmd.Decision != domain.DecisionDeny || roCmd.Status != domain.AuthorStatusFail {
		t.Fatalf("readonly configure must deny: %+v", roCmd)
	}
	if roCmd.Trace.Winner == nil || roCmd.Trace.Winner.RuleID != "deny-everything-else" {
		t.Fatalf("readonly configure winner: %+v", roCmd.Trace.Winner)
	}
	for _, s := range roCmd.Trace.Steps {
		if s.Kind == string(domain.RuleKindService) {
			t.Fatalf("command walk must not consider service rules: %+v", s)
		}
	}
}

func TestServicePermitNeverAuthorizesCommand(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")
	res := eng.EvaluateService(cmdReq("lab-readonly", "lab-switches", "configure"))
	if res.Decision != domain.DecisionDeny {
		t.Fatalf("EvaluateService(configure) = %s", res.Decision)
	}
	if res.Trace.DefaultDeny != "service evaluator does not authorize commands" {
		t.Fatalf("reason=%q", res.Trace.DefaultDeny)
	}
	if res.Trace.Winner != nil {
		t.Fatalf("no winner: %+v", res.Trace.Winner)
	}

	sess := eng.EvaluateCommand(sessionReq("lab-admin", "lab-switches"))
	if sess.Decision != domain.DecisionDeny {
		t.Fatalf("EvaluateCommand(session) = %s", sess.Decision)
	}
	if sess.Trace.DefaultDeny != "command evaluator does not decide session requests" {
		t.Fatalf("reason=%q", sess.Trace.DefaultDeny)
	}
}

func TestDefaultGroupIDsAppendDedup(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")

	guest := eng.Authorize(sessionReq("lab-guest", "lab-switches"))
	if guest.Decision != domain.DecisionPermitAdd || !guest.Arguments.Equal(domain.AVPairs{av("priv-lvl", '=', "1")}) {
		t.Fatalf("guest inherits client default readonly: %+v", guest)
	}
	if len(guest.Trace.EffectiveGroupIDs) != 1 || guest.Trace.EffectiveGroupIDs[0] != "readonly" {
		t.Fatalf("guest groups: %v", guest.Trace.EffectiveGroupIDs)
	}

	admin := eng.Authorize(sessionReq("lab-admin", "lab-switches"))
	if len(admin.Trace.EffectiveGroupIDs) != 2 {
		t.Fatalf("admin+default groups: %v", admin.Trace.EffectiveGroupIDs)
	}
	if admin.Trace.EffectiveGroupIDs[0] != "administrators" || admin.Trace.EffectiveGroupIDs[1] != "readonly" {
		t.Fatalf("walk order by priority then id: %v", admin.Trace.EffectiveGroupIDs)
	}
}

func TestUserRulesBeforeGroups(t *testing.T) {
	t.Parallel()
	in := Input{
		Groups: []config.Group{{
			ID:      "administrators",
			Enabled: true,
			Services: []config.ServiceRule{{
				Service:         "shell",
				Action:          domain.DecisionPermitAdd,
				ReplyAttributes: domain.AVPairs{av("priv-lvl", '=', "15")},
			}},
			CommandRules: []config.CommandRule{{
				ID:        "permit-all",
				Priority:  10,
				Action:    domain.DecisionPermitAdd,
				Command:   config.StringMatch{Pattern: ".*"},
				Arguments: config.StringMatch{Pattern: ".*"},
			}},
		}},
		Users: []config.User{{
			ID:       "ops",
			Enabled:  true,
			GroupIDs: []string{"administrators"},
			Rules: config.RuleSet{
				Services: []config.ServiceRule{{
					Service:         "shell",
					Action:          domain.DecisionPermitReplace,
					ReplyAttributes: domain.AVPairs{av("priv-lvl", '=', "7")},
				}},
				CommandRules: []config.CommandRule{{
					ID:        "deny-cfg",
					Priority:  1,
					Action:    domain.DecisionDeny,
					Command:   config.StringMatch{Exact: "configure"},
					Arguments: config.StringMatch{Pattern: ".*"},
				}},
			},
		}},
	}
	eng := mustCompile(t, in)
	sess := eng.Authorize(sessionReq("ops", ""))
	if sess.Decision != domain.DecisionPermitReplace || sess.Status != domain.AuthorStatusPassRepl {
		t.Fatalf("user service wins: %+v", sess)
	}
	if !sess.Arguments.Equal(domain.AVPairs{av("priv-lvl", '=', "7")}) {
		t.Fatalf("user reply: %+v", sess.Arguments)
	}
	if sess.Trace.Winner.Source != sourceUser {
		t.Fatalf("source=%q", sess.Trace.Winner.Source)
	}

	deny := eng.Authorize(cmdReq("ops", "", "configure"))
	if deny.Decision != domain.DecisionDeny || deny.Trace.Winner.RuleID != "deny-cfg" {
		t.Fatalf("user command deny before group permit-all: %+v", deny)
	}
}

func TestGroupPriorityThenID(t *testing.T) {
	t.Parallel()
	in := Input{
		Groups: []config.Group{
			{
				ID:       "zeta",
				Enabled:  true,
				Priority: 50,
				Services: []config.ServiceRule{{
					Service:         "shell",
					Action:          domain.DecisionPermitAdd,
					ReplyAttributes: domain.AVPairs{av("priv-lvl", '=', "1")},
				}},
			},
			{
				ID:       "alpha",
				Enabled:  true,
				Priority: 50,
				Services: []config.ServiceRule{{
					Service:         "shell",
					Action:          domain.DecisionPermitAdd,
					ReplyAttributes: domain.AVPairs{av("priv-lvl", '=', "5")},
				}},
			},
			{
				ID:       "first",
				Enabled:  true,
				Priority: 1,
				Services: []config.ServiceRule{{
					Service:         "shell",
					Action:          domain.DecisionPermitAdd,
					ReplyAttributes: domain.AVPairs{av("priv-lvl", '=', "15")},
				}},
			},
		},
		Users: []config.User{{
			ID:       "u",
			Enabled:  true,
			GroupIDs: []string{"zeta", "alpha", "first"},
		}},
	}
	eng := mustCompile(t, in)
	res := eng.Authorize(sessionReq("u", ""))
	if res.Trace.Winner == nil || res.Trace.Winner.Source != "group:first" {
		t.Fatalf("lowest priority wins: %+v", res.Trace.Winner)
	}
	if !res.Arguments.Equal(domain.AVPairs{av("priv-lvl", '=', "15")}) {
		t.Fatalf("avs=%+v", res.Arguments)
	}

	in.Groups[2].Enabled = false
	eng = mustCompile(t, in)
	res = eng.Authorize(sessionReq("u", ""))
	if res.Trace.Winner == nil || res.Trace.Winner.Source != "group:alpha" {
		t.Fatalf("same priority, id order: %+v", res.Trace.Winner)
	}
}

func TestFallbackAfterGroups(t *testing.T) {
	t.Parallel()
	in := Input{
		Users: []config.User{{ID: "u", Enabled: true}},
		Fallback: config.RuleSet{
			Services: []config.ServiceRule{{
				Service:         "shell",
				Action:          domain.DecisionPermitAdd,
				ReplyAttributes: domain.AVPairs{av("priv-lvl", '=', "0")},
			}},
			CommandRules: []config.CommandRule{
				{
					ID:        "late",
					Priority:  20,
					Action:    domain.DecisionDeny,
					Command:   config.StringMatch{Pattern: ".*"},
					Arguments: config.StringMatch{Pattern: ".*"},
				},
				{
					ID:        "early",
					Priority:  5,
					Action:    domain.DecisionPermitAdd,
					Command:   config.StringMatch{Exact: "show"},
					Arguments: config.StringMatch{Pattern: ".*"},
				},
			},
		},
	}
	eng := mustCompile(t, in)
	sess := eng.Authorize(sessionReq("u", ""))
	if sess.Trace.Winner == nil || sess.Trace.Winner.Source != sourceFallback {
		t.Fatalf("fallback service: %+v", sess)
	}
	cmd := eng.Authorize(cmdReq("u", "", "show", "ver"))
	if cmd.Trace.Winner == nil || cmd.Trace.Winner.RuleID != "early" {
		t.Fatalf("fallback command order by priority: %+v", cmd.Trace.Winner)
	}
}

func TestDefaultDenyUnknownAndDisabled(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")
	unknown := eng.Authorize(sessionReq("nope", "lab-switches"))
	if unknown.Decision != domain.DecisionDeny || unknown.Trace.DefaultDeny != "user not found" {
		t.Fatalf("unknown: %+v", unknown)
	}
	disabled := eng.Authorize(sessionReq("lab-disabled", "lab-switches"))
	if disabled.Decision != domain.DecisionDeny || disabled.Trace.DefaultDeny != "user disabled" {
		t.Fatalf("disabled: %+v", disabled)
	}
	nomatch := eng.Authorize(Request{UserID: "lab-guest", ClientID: "", Service: "ppp"})
	if nomatch.Decision != domain.DecisionDeny || nomatch.Trace.DefaultDeny != "no matching service rule" {
		t.Fatalf("no match: %+v", nomatch)
	}
	bare := mustCompile(t, Input{Users: []config.User{{ID: "solo", Enabled: true}}})
	cmdDeny := bare.Authorize(cmdReq("solo", "", "show"))
	if cmdDeny.Decision != domain.DecisionDeny || cmdDeny.Trace.DefaultDeny != "no matching command rule" {
		t.Fatalf("command default deny: %+v", cmdDeny)
	}
	if cmdDeny.Status == domain.AuthorStatusFollow {
		t.Fatal("FOLLOW must not be emitted")
	}
}

func TestAuthenMethodObservational(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")
	a := sessionReq("lab-admin", "lab-switches")
	a.AuthenMethod = domain.AuthenTypeASCII
	b := a
	b.AuthenMethod = domain.AuthenTypePAP
	ra, rb := eng.Authorize(a), eng.Authorize(b)
	if ra.Decision != rb.Decision || !ra.Arguments.Equal(rb.Arguments) {
		t.Fatalf("authen_method must not change decision: %+v vs %+v", ra, rb)
	}
	if ra.Trace.Winner.Source != rb.Trace.Winner.Source || ra.Trace.Winner.RuleID != rb.Trace.Winner.RuleID {
		t.Fatalf("winner changed: %+v vs %+v", ra.Trace.Winner, rb.Trace.Winner)
	}
	if ra.Trace.AuthenMethod == rb.Trace.AuthenMethod {
		t.Fatal("trace should record the reported method")
	}
}

func TestAVOrderDuplicatesAndSeparators(t *testing.T) {
	t.Parallel()
	in := Input{
		Users: []config.User{{
			ID:      "u",
			Enabled: true,
			Rules: config.RuleSet{Services: []config.ServiceRule{{
				Service: "shell",
				Action:  domain.DecisionPermitReplace,
				ReplyAttributes: domain.AVPairs{
					av("priv-lvl", '=', "15"),
					av("priv-lvl", '=', "15"),
					av("inacl", '*', "std"),
					av("cisco-av-pair", '=', "shell:roles=admin"),
					av("addr", '=', "2001:db8::1"),
				},
			}}},
		}},
	}
	eng := mustCompile(t, in)
	res := eng.Authorize(sessionReq("u", ""))
	if res.Status != domain.AuthorStatusPassRepl {
		t.Fatalf("status=%s", res.Status)
	}
	want := domain.AVPairs{
		av("priv-lvl", '=', "15"),
		av("priv-lvl", '=', "15"),
		av("inacl", '*', "std"),
		av("cisco-av-pair", '=', "shell:roles=admin"),
		av("addr", '=', "2001:db8::1"),
	}
	if !res.Arguments.Equal(want) {
		t.Fatalf("order/dups/separators: got %+v", res.Arguments)
	}
}

func TestProtocolMatchAndEmptyCmdFromAV(t *testing.T) {
	t.Parallel()
	in := Input{
		Users: []config.User{{
			ID:      "u",
			Enabled: true,
			Rules: config.RuleSet{Services: []config.ServiceRule{{
				Service:         "ppp",
				Protocol:        strPtr("ip"),
				Action:          domain.DecisionPermitAdd,
				ReplyAttributes: domain.AVPairs{av("addr", '=', "192.0.2.1")},
			}}},
		}},
	}
	eng := mustCompile(t, in)
	miss := eng.Authorize(Request{UserID: "u", Service: "ppp", Protocol: "ipv6"})
	if miss.Decision != domain.DecisionDeny {
		t.Fatalf("protocol mismatch must deny: %s", miss.Decision)
	}
	hit := eng.Authorize(Request{
		UserID: "u",
		Arguments: domain.AVPairs{
			av("service", '=', "ppp"),
			av("protocol", '=', "ip"),
			av("cmd", '=', ""),
		},
	})
	if hit.Decision != domain.DecisionPermitAdd {
		t.Fatalf("empty cmd AV is session: %+v", hit)
	}
}

func TestCommandRegexAndEmptyArgs(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")
	tr := eng.Authorize(cmdReq("lab-readonly", "lab-switches", "traceroute6", "2001:db8::1"))
	if tr.Decision != domain.DecisionPermitAdd || tr.Trace.Winner.RuleID != "traceroute" {
		t.Fatalf("traceroute6: %+v", tr)
	}
	show := eng.Authorize(cmdReq("lab-readonly", "lab-switches", "show"))
	if show.Decision != domain.DecisionPermitAdd {
		t.Fatalf("show with no args: %+v", show)
	}
	dup := eng.Authorize(cmdReq("lab-readonly", "lab-switches", "show", "ip", "ip"))
	if dup.Decision != domain.DecisionPermitAdd || len(dup.Trace.CmdArgs) != 2 {
		t.Fatalf("duplicate cmd-arg preserved: %+v", dup.Trace.CmdArgs)
	}
}

func TestClientRestrictionAndValidityWindow(t *testing.T) {
	t.Parallel()
	after := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	in := Input{
		Clients: []config.Client{{ID: "sw", Enabled: true}},
		Users: []config.User{{
			ID:      "u",
			Enabled: true,
			Rules: config.RuleSet{Services: []config.ServiceRule{{
				Service: "shell",
				Action:  domain.DecisionPermitAdd,
			}}},
			Restrictions: config.UserRestrictions{
				ClientIDs:   []string{"sw"},
				ValidAfter:  &after,
				ValidBefore: &before,
			},
		}},
		Now: func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) },
	}
	eng := mustCompile(t, in)
	if res := eng.Authorize(sessionReq("u", "sw")); res.Decision != domain.DecisionPermitAdd {
		t.Fatalf("in window: %+v", res)
	}
	if res := eng.Authorize(sessionReq("u", "other")); res.Decision != domain.DecisionDeny {
		t.Fatalf("wrong client: %+v", res)
	}
	in.Now = func() time.Time { return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) }
	eng = mustCompile(t, in)
	if res := eng.Authorize(sessionReq("u", "sw")); res.Trace.DefaultDeny != "user not valid at evaluation time" {
		t.Fatalf("before window: %+v", res)
	}
}

func TestCompileDefaultClockEnforcesValidityWindow(t *testing.T) {
	t.Parallel()
	expired := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	in := Input{
		Users: []config.User{{
			ID:      "u",
			Enabled: true,
			Rules: config.RuleSet{Services: []config.ServiceRule{{
				Service: "shell",
				Action:  domain.DecisionPermitAdd,
			}}},
			Restrictions: config.UserRestrictions{ValidBefore: &expired},
		}},
	}
	eng := mustCompile(t, in)
	if res := eng.Authorize(sessionReq("u", "")); res.Trace.DefaultDeny != "user not valid at evaluation time" {
		t.Fatalf("omitted Now must use time.Now: %+v", res)
	}
	doc := mustParseFile(t, "policies", "personas.yaml")
	doc.Users = append(doc.Users, config.User{
		ID:           "expired",
		Enabled:      true,
		Restrictions: config.UserRestrictions{ValidBefore: &expired},
		Rules: config.RuleSet{Services: []config.ServiceRule{{
			Service: "shell",
			Action:  domain.DecisionPermitAdd,
		}}},
	})
	fromDoc, err := CompileDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	if res := fromDoc.Authorize(sessionReq("expired", "")); res.Trace.DefaultDeny != "user not valid at evaluation time" {
		t.Fatalf("CompileDocument must not skip windows: %+v", res)
	}
}

func TestFOLLOWNeverEmittedAndErrorVsDeny(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")
	res := eng.Authorize(sessionReq("missing", ""))
	if res.Status == domain.AuthorStatusFollow || res.Status == domain.AuthorStatusError {
		t.Fatalf("deny must be FAIL: %s", res.Status)
	}
	nilEng := (*Engine)(nil)
	errRes := nilEng.Authorize(sessionReq("u", ""))
	if errRes.Status != domain.AuthorStatusError {
		t.Fatalf("nil engine: %s", errRes.Status)
	}
}

func TestDeterministicOrderAcrossRuns(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")
	req := cmdReq("lab-readonly", "lab-switches", "configure")
	var first Result
	for i := 0; i < 20; i++ {
		got := eng.Authorize(req)
		if i == 0 {
			first = got
			continue
		}
		if got.Decision != first.Decision || got.Trace.Winner.RuleID != first.Trace.Winner.RuleID {
			t.Fatalf("run %d diverged", i)
		}
		if len(got.Trace.Steps) != len(first.Trace.Steps) {
			t.Fatalf("step count %d vs %d", len(got.Trace.Steps), len(first.Trace.Steps))
		}
		for j := range got.Trace.Steps {
			if got.Trace.Steps[j] != first.Trace.Steps[j] {
				t.Fatalf("step %d: %+v vs %+v", j, got.Trace.Steps[j], first.Trace.Steps[j])
			}
		}
	}
}

func TestCompileRejectsBadRegexAndBadReply(t *testing.T) {
	t.Parallel()
	_, err := Compile(Input{Users: []config.User{{
		ID:      "u",
		Enabled: true,
		Rules: config.RuleSet{CommandRules: []config.CommandRule{{
			ID:        "bad",
			Action:    domain.DecisionPermitAdd,
			Command:   config.StringMatch{Pattern: "("},
			Arguments: config.StringMatch{Exact: ""},
		}}},
	}}})
	if err == nil {
		t.Fatal("expected regex compile error")
	}
	_, err = Compile(Input{Users: []config.User{{
		ID:      "u",
		Enabled: true,
		Rules: config.RuleSet{Services: []config.ServiceRule{{
			Service:         "shell",
			Action:          domain.DecisionPermitAdd,
			ReplyAttributes: domain.AVPairs{av("priv-lvl", '=', "99")},
		}}},
	}}})
	if err == nil {
		t.Fatal("expected priv-lvl compile error")
	}
}

func TestResponseArgumentLimitIsError(t *testing.T) {
	t.Parallel()
	reply := domain.AVPairs{av("priv-lvl", '=', "1"), av("autocmd", '=', "show")}
	eng := mustCompile(t, Input{
		Limits: config.Limits{MaxAuthorizationArguments: 1},
		Users: []config.User{{
			ID:      "u",
			Enabled: true,
			Rules:   config.RuleSet{Services: []config.ServiceRule{{Service: "shell", Action: domain.DecisionPermitAdd, ReplyAttributes: reply}}},
		}},
	})
	res := eng.Authorize(sessionReq("u", ""))
	if res.Status != domain.AuthorStatusError {
		t.Fatalf("over-limit reply must be ERROR not deny: %+v", res)
	}
}
