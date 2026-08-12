package aaa

import (
	"context"
	"reflect"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/policy"
)

func TestLiveAndExplainIdentical(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	ctx := context.Background()
	reqs := []AuthorizationRequest{
		{
			UserID: "lab-admin", ClientID: "lab-switches",
			Arguments:     domain.AVPairs{av("service", '=', "shell"), av("cmd", '=', "")},
			AuthenMethod:  domain.AuthenMethodTACACS,
			AuthenType:    domain.AuthenTypeASCII,
			AuthenService: domain.AuthenServiceLogin,
			Port:          "ttyS0", Remote: "192.0.2.8",
		},
		{
			UserID: "lab-admin", ClientID: "lab-switches",
			Arguments:     domain.AVPairs{av("service", '=', "shell"), av("cmd", '=', "configure")},
			AuthenMethod:  domain.AuthenMethodLocal,
			AuthenType:    domain.AuthenTypePAP,
			AuthenService: domain.AuthenServiceLogin,
			Port:          "ttyS0", Remote: "192.0.2.8",
		},
		{
			UserID: "lab-readonly", ClientID: "lab-switches",
			Arguments: domain.AVPairs{av("service", '=', "shell"), av("cmd", '=', "configure")},
			Port:      "con0", Remote: "2001:db8::8",
		},
	}
	before := ring.Len()
	for i, req := range reqs {
		live, err := svc.Authorize(ctx, req)
		if err != nil {
			t.Fatalf("live %d: %v", i, err)
		}
		explain, err := svc.ExplainAuthorization(ctx, req)
		if err != nil {
			t.Fatalf("explain %d: %v", i, err)
		}
		if live.Decision.String() != explain.Decision || live.Status.String() != explain.Status {
			t.Fatalf("case %d decision live=%s/%s explain=%s/%s", i, live.Decision, live.Status, explain.Decision, explain.Status)
		}
		if !sameTrace(live.Trace, explain) {
			t.Fatalf("case %d trace mismatch\nlive=%+v\nexplain=%+v", i, live.Trace, explain)
		}
	}
	if ring.Len() != before+len(reqs) {
		t.Fatalf("explain must not record: before=%d after=%d", before, ring.Len())
	}
}

func TestAuthorizePreservesRequestFieldsAndDictionary(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	args := domain.AVPairs{
		av("service", '=', "shell"),
		av("protocol", '=', ""),
		av("cmd", '=', ""),
		av("cmd-arg", '=', "unused"),
		av("acl", '=', "12"),
		av("inacl", '*', "std-in"),
		av("outacl", '=', "std-out"),
		av("addr", '=', "192.0.2.1"),
		av("addr-pool", '=', "lab-pool"),
		av("timeout", '=', "30"),
		av("idletime", '=', "5"),
		av("autocmd", '=', "show version"),
		av("noescape", '=', "true"),
		av("nohangup", '=', "false"),
		av("priv-lvl", '=', "1"),
		av("timezone", '=', "UTC"),
		av("start_time", '=', "1755000000"),
		av("stop_time", '=', "1755003600"),
		av("vendor-x", '=', "keep=this*value"),
	}
	if got, want := len(args), len(policy.KnownArgs())+1; got != want {
		t.Fatalf("dictionary coverage %d want %d known + 1 vendor", got, want)
	}
	for _, spec := range policy.KnownArgs() {
		if err := policy.ValidateValue(spec.Name, firstNamed(args, spec.Name)); err != nil {
			t.Fatalf("dictionary %s: %v", spec.Name, err)
		}
	}
	dec, err := svc.Authorize(context.Background(), AuthorizationRequest{
		UserID: "lab-admin", ClientID: "lab-switches",
		Arguments:     args,
		AuthenMethod:  domain.AuthenMethodKRB5,
		AuthenType:    domain.AuthenTypeASCII,
		AuthenService: domain.AuthenServiceLogin,
		Privilege:     1,
		Port:          "tty0",
		Remote:        "192.0.2.50",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != domain.DecisionPermitAdd || dec.Status != domain.AuthorStatusPassAdd {
		t.Fatalf("session=%+v", dec)
	}
	tr := dec.Trace
	if tr.Evaluator != string(domain.RuleKindService) {
		t.Fatalf("evaluator=%s", tr.Evaluator)
	}
	if tr.UserID != "lab-admin" || tr.Port != "tty0" || tr.Remote != "192.0.2.50" {
		t.Fatalf("identity fields: %+v", tr)
	}
	if tr.AuthenMethod != "krb5" || tr.AuthenType != "ascii" || tr.AuthenService != "login" {
		t.Fatalf("auth context: method=%s type=%s svc=%s", tr.AuthenMethod, tr.AuthenType, tr.AuthenService)
	}
	if len(tr.RequestArguments) != len(args) {
		t.Fatalf("request AV count %d want %d", len(tr.RequestArguments), len(args))
	}
	for i, a := range args {
		got := tr.RequestArguments[i]
		if got.Name != a.Name || got.Separator != string([]byte{a.Separator}) || got.Value != a.Value {
			t.Fatalf("request AV[%d]=%+v want %+v", i, got, a)
		}
	}
	if !dec.Arguments.Equal(domain.AVPairs{av("priv-lvl", '=', "15")}) {
		t.Fatalf("PASS_ADD reply=%+v", dec.Arguments)
	}
}

func TestAuthenMethodCodesRecordedNotTrusted(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	req := AuthorizationRequest{
		UserID: "lab-admin", ClientID: "lab-switches",
		Arguments: domain.AVPairs{av("service", '=', "shell")},
	}
	methods := []domain.AuthenMethod{
		domain.AuthenMethodNotSet, domain.AuthenMethodNone, domain.AuthenMethodKRB5,
		domain.AuthenMethodLine, domain.AuthenMethodEnable, domain.AuthenMethodLocal,
		domain.AuthenMethodTACACS, domain.AuthenMethodGuest, domain.AuthenMethodRADIUS,
		domain.AuthenMethodKRB4, domain.AuthenMethodRCMD,
	}
	var first PolicyTrace
	for i, m := range methods {
		req.AuthenMethod = m
		dec, err := svc.ExplainAuthorization(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if dec.AuthenMethod != m.String() {
			t.Fatalf("method %v traced as %q", m, dec.AuthenMethod)
		}
		if i == 0 {
			first = dec
			continue
		}
		if dec.Decision != first.Decision || dec.Status != first.Status {
			t.Fatalf("authen_method %s changed decision to %s/%s", m, dec.Decision, dec.Status)
		}
	}
}

func TestWireAVsWinOverTypedCmd(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	// lab-admin permits configure only. Typed show would deny; AV configure must permit.
	dec, err := svc.Authorize(context.Background(), AuthorizationRequest{
		UserID: "lab-admin", ClientID: "lab-switches",
		Service: "shell", Cmd: "show", CmdArgs: []string{"ver"},
		Arguments: domain.AVPairs{
			av("service", '=', "shell"),
			av("cmd", '=', "configure"),
			av("cmd-arg", '=', "terminal"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != domain.DecisionPermitAdd || dec.Status != domain.AuthorStatusPassAdd {
		t.Fatalf("AV cmd=configure must win over typed show: %+v", dec)
	}
	if dec.Trace.Cmd != "configure" || dec.Trace.Evaluator != string(domain.RuleKindCommand) {
		t.Fatalf("trace cmd/evaluator=%s/%s", dec.Trace.Cmd, dec.Trace.Evaluator)
	}
	if !reflect.DeepEqual(dec.Trace.CmdArgs, []string{"terminal"}) {
		t.Fatalf("cmd-arg from AV: %v", dec.Trace.CmdArgs)
	}
}

func TestSensitiveRequestAVsRedactedInTrace(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	dec, err := svc.Authorize(context.Background(), AuthorizationRequest{
		UserID: "lab-admin", ClientID: "lab-switches",
		Arguments: domain.AVPairs{
			av("service", '=', "shell"),
			av("password", '=', "labpass1!"),
			av("shared-secret", '=', "LabSecret-16chars!"),
			av("token", '=', "live-token-value"),
			av("tacacs-key", '=', "LabSecret-16chars!"),
			av("ms-chap", '=', "challenge-material"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantRedact := map[string]struct{}{
		"password": {}, "shared-secret": {}, "token": {}, "tacacs-key": {}, "ms-chap": {},
	}
	for _, a := range dec.Trace.RequestArguments {
		if _, ok := wantRedact[a.Name]; !ok {
			continue
		}
		if a.Value != "[redacted]" {
			t.Fatalf("%s not redacted: %q", a.Name, a.Value)
		}
	}
	if !dec.Arguments.Equal(domain.AVPairs{av("priv-lvl", '=', "15")}) {
		t.Fatalf("wire/decision args must stay unredacted: %+v", dec.Arguments)
	}

	eng, err := policy.Compile(policy.Input{Users: []config.User{{
		ID:      "u",
		Enabled: true,
		Rules: config.RuleSet{Services: []config.ServiceRule{{
			Service: "shell",
			Action:  domain.DecisionPermitAdd,
			ReplyAttributes: domain.AVPairs{
				av("token", '=', "live-token-value"),
				av("tacacs-key", '=', "wire-key"),
			},
		}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tr, res, err := Evaluate(eng, AuthorizationRequest{
		UserID: "u",
		Arguments: domain.AVPairs{
			av("service", '=', "shell"),
			av("token", '=', "request-token"),
			av("tacacs-key", '=', "request-key"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Arguments.Equal(domain.AVPairs{av("token", '=', "live-token-value"), av("tacacs-key", '=', "wire-key")}) {
		t.Fatalf("decision args must not be redacted: %+v", res.Arguments)
	}
	for _, a := range tr.RequestArguments {
		if (a.Name == "token" || a.Name == "tacacs-key") && a.Value != "[redacted]" {
			t.Fatalf("request %s leaked: %q", a.Name, a.Value)
		}
	}
	for _, a := range tr.Arguments {
		if (a.Name == "token" || a.Name == "tacacs-key") && a.Value != "[redacted]" {
			t.Fatalf("trace reply %s leaked: %q", a.Name, a.Value)
		}
	}
}

func TestPASSAddZeroArgsForCommand(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	cmd, err := svc.Authorize(context.Background(), AuthorizationRequest{
		UserID: "lab-admin", ClientID: "lab-switches",
		Arguments: domain.AVPairs{av("service", '=', "shell"), av("cmd", '=', "configure")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Status != domain.AuthorStatusPassAdd || len(cmd.Arguments) != 0 {
		t.Fatalf("PASS_ADD zero args: %+v", cmd)
	}
	if cmd.Trace.Evaluator != string(domain.RuleKindCommand) {
		t.Fatalf("evaluator=%s", cmd.Trace.Evaluator)
	}
}

func sameTrace(a, b PolicyTrace) bool {
	return reflect.DeepEqual(a, b)
}

func firstNamed(args domain.AVPairs, name string) string {
	for _, a := range args {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}
