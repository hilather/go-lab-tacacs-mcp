package aaa

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestASCIILoginPassAndFail(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	start := AuthenticationStart{
		ConnKey: 1, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}
	step, err := svc.BeginAuthentication(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || !step.NoEcho {
		t.Fatalf("start=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 1, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("pass status=%s", step.Status)
	}

	start.SessionID = 2
	if _, err := svc.BeginAuthentication(ctx, start); err != nil {
		t.Fatal(err)
	}
	step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 1, SessionID: 2, UserMsg: []byte("wrong-password"), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass {
		t.Fatalf("retry want GETPASS got %s", step.Status)
	}
}

func TestASCIIUnknownUserUniformFail(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	start := AuthenticationStart{
		ConnKey: 2, SessionID: 1, UserID: "no-such-user", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}
	step, err := svc.BeginAuthentication(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass {
		t.Fatalf("unknown user must still GETPASS, got %s", step.Status)
	}
	// Exhaust retries so the last result is FAIL, same as a known bad password.
	var last AuthenticationStep
	for i := 0; i < 16; i++ {
		last, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
			ConnKey: 2, SessionID: 1, UserMsg: []byte("whatever"), ClientID: "lab-switches",
		})
		if err != nil {
			t.Fatal(err)
		}
		if last.Status == domain.AuthenStatusFail {
			break
		}
	}
	if last.Status != domain.AuthenStatusFail {
		t.Fatalf("unknown user terminal=%s", last.Status)
	}
}

func TestASCIIMissingUserPrompts(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	step, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 3, SessionID: 1, ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetUser {
		t.Fatalf("status=%s", step.Status)
	}
	step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 3, SessionID: 1, UserMsg: []byte("lab-admin"), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || !step.NoEcho {
		t.Fatalf("after user=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 3, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("pass=%s", step.Status)
	}
}

func TestUnimplementedFlowsError(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	cases := []AuthenticationStart{
		{ConnKey: 4, SessionID: 1, Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin},
		{ConnKey: 4, SessionID: 2, Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceEnable},
		{ConnKey: 4, SessionID: 3, Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin},
	}
	for _, start := range cases {
		step, err := svc.BeginAuthentication(ctx, start)
		if err != nil {
			t.Fatalf("%+v: %v", start, err)
		}
		if step.Status != domain.AuthenStatusError {
			t.Fatalf("%+v status=%s", start, step.Status)
		}
	}
}

func TestASCIIDisallowedRestarts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := filepath.Join(dir, "shared")
	if err := os.WriteFile(sec, []byte(testSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	src := `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: chap-only
    priority: 10
    match: {source_cidrs: ["10.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: ` + sec + `}}
    authentication: {allowed_methods: [chap]}
`
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(config.SecretRef) ([]byte, error) { return []byte(testSecret), nil }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Options{
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
		Creds:    credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 5, SessionID: 1, ClientID: "chap-only",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusRestart {
		t.Fatalf("status=%s", step.Status)
	}
}

func TestAbortDropsSession(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 6, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.AbortAuthentication(ctx, AuthenticationAbort{ConnKey: 6, SessionID: 1, ClientID: "lab-switches"}); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 6, SessionID: 1, UserMsg: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusError {
		t.Fatalf("after abort=%s", step.Status)
	}
}

func TestNewRequiresSnapshot(t *testing.T) {
	t.Parallel()
	_, err := New(Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	var de domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeInvalidArgument {
		t.Fatalf("err=%v", err)
	}
}
