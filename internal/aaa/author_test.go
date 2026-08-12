package aaa

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestAuthorizeServiceVsCommand(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()

	sess, err := svc.Authorize(ctx, AuthorizationRequest{
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Service:  "shell",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Decision != domain.DecisionPermitAdd || sess.Status != domain.AuthorStatusPassAdd {
		t.Fatalf("session=%+v", sess)
	}
	if sess.Trace.Evaluator != string(domain.RuleKindService) {
		t.Fatalf("evaluator=%s", sess.Trace.Evaluator)
	}
	found := false
	for _, a := range sess.Arguments {
		if a.Name == "priv-lvl" && a.Value == "15" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing priv-lvl 15: %+v", sess.Arguments)
	}

	cmd, err := svc.Authorize(ctx, AuthorizationRequest{
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Service:  "shell",
		Cmd:      "configure",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Decision != domain.DecisionPermitAdd {
		t.Fatalf("configure=%+v", cmd)
	}
	if cmd.Trace.Evaluator != string(domain.RuleKindCommand) {
		t.Fatalf("cmd evaluator=%s", cmd.Trace.Evaluator)
	}

	deny, err := svc.Authorize(ctx, AuthorizationRequest{
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Service:  "shell",
		Cmd:      "reload",
	})
	if err != nil {
		t.Fatal(err)
	}
	if deny.Decision != domain.DecisionDeny || deny.Status != domain.AuthorStatusFail {
		t.Fatalf("reload should deny, got %+v", deny)
	}
}

func TestServicePermitNeverAuthorizesCommand(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	// Empty cmd uses the service evaluator. A non-empty cmd must not
	// inherit the shell permit.
	tr, err := svc.ExplainAuthorization(context.Background(), AuthorizationRequest{
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Service:  "shell",
		Cmd:      "configure",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Evaluator != string(domain.RuleKindCommand) {
		t.Fatalf("evaluator=%s", tr.Evaluator)
	}
	for _, st := range tr.Steps {
		if st.Kind == string(domain.RuleKindService) {
			t.Fatalf("command walk consulted a service rule: %+v", st)
		}
	}
}

func TestExplainDoesNotRequireRing(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	before := ring.Len()
	_, err := svc.ExplainAuthorization(context.Background(), AuthorizationRequest{
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Service:  "shell",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ring.Len() != before {
		t.Fatalf("explain recorded an event: %d -> %d", before, ring.Len())
	}
}
