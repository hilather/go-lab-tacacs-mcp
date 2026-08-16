package aaa

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func setMustChangeLogin(t testing.TB, mgr *state.Manager, id string, v bool) {
	t.Helper()
	rev := mgr.Revision()
	if _, err := mgr.UpdateUser(id, state.UpdateUser{MustChangeLogin: &v}, &rev); err != nil {
		t.Fatal(err)
	}
}

func setMustChangeEnable(t testing.TB, mgr *state.Manager, id string, v bool) {
	t.Helper()
	rev := mgr.Revision()
	if _, err := mgr.UpdateUser(id, state.UpdateUser{MustChangeEnable: &v}, &rev); err != nil {
		t.Fatal(err)
	}
}

func enableStart(conn uint64, sess uint32) AuthenticationStart {
	return AuthenticationStart{
		ConnKey: conn, SessionID: sess, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceEnable,
	}
}

func asciiLoginStart(conn uint64, sess uint32) AuthenticationStart {
	return AuthenticationStart{
		ConnKey: conn, SessionID: sess, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}
}

func continueMsg(conn uint64, sess uint32, msg string) AuthenticationContinue {
	return AuthenticationContinue{ConnKey: conn, SessionID: sess, UserMsg: []byte(msg), ClientID: "lab-switches"}
}

func TestASCIILoginMustChangePromptsAndPass(t *testing.T) {
	t.Parallel()
	svc, mgr, ring := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	const next = "newpass-ok1!"
	beforeEvents := len(ring.Snapshot())
	step, err := svc.BeginAuthentication(ctx, asciiLoginStart(40, 1))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptPass || !step.NoEcho {
		t.Fatalf("old prompt=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(40, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptNewPass || !step.NoEcho {
		t.Fatalf("new prompt=%+v", step)
	}
	if n := len(ring.Snapshot()); n != beforeEvents {
		t.Fatalf("no terminal event at extra GETPASS, before=%d after=%d", beforeEvents, n)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(40, 1, next))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptConfirm || !step.NoEcho {
		t.Fatalf("confirm prompt=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(40, 1, next))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("pass=%s", step.Status)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if u.User.MustChangeLogin {
		t.Fatal("flag must clear")
	}
	if u.User.Credentials.Challenge.Secret.File == "" {
		t.Fatal("challenge must be untouched")
	}
	if u.User.Credentials.Enable.Verifier.File == "" {
		t.Fatal("enable must be untouched")
	}
	var sawLogin bool
	for _, ev := range ring.Snapshot() {
		if ev.Type == "ascii_chpass" {
			t.Fatalf("in-LOGIN must not emit ascii_chpass: %+v", ev)
		}
		if ev.Type == "ascii_login" && ev.Result == "pass" {
			sawLogin = true
			if ev.ReasonCode != reasonPasswordChanged {
				t.Fatalf("reason=%q", ev.ReasonCode)
			}
		}
	}
	if !sawLogin {
		t.Fatal("missing ascii_login pass event")
	}

	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 40, SessionID: 2, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(next),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("new password pap=%s", step.Status)
	}
}

func TestContinueASCIIDispatchesNeedNew(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(41, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(41, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.ServerMsg != promptNewPass {
		t.Fatalf("want New Password, got %+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(41, 1, "brand-new-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptConfirm {
		t.Fatalf("second CONTINUE must confirm, not re-verify: %+v", step)
	}
}

func TestASCIILoginMustChangeWrongPasswordUniform(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(42, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(42, 1, "wrong-password"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptPass {
		t.Fatalf("wrong password must stay uniform GETPASS Password:, got %+v", step)
	}
}

func TestASCIILoginMustChangeUnknownUserUniform(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	start := AuthenticationStart{
		ConnKey: 43, SessionID: 1, UserID: "no-such-user", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}
	if _, err := svc.BeginAuthentication(ctx, start); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 43, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.ServerMsg == promptNewPass {
		t.Fatal("unknown user must not get New Password")
	}
}

func TestMustChangeDoesNotOverrideKindExpired(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	rev := mgr.Revision()
	if _, err := mgr.UpdateUser("lab-admin", state.UpdateUser{
		MustChangeLogin: boolPtr(true),
		Restrictions:    &config.UserRestrictions{ValidBefore: &past},
	}, &rev); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(44, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(44, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.ServerMsg == promptNewPass || step.ServerMsg == serverMsgPasswordChangeRequired {
		t.Fatalf("expired+flag must stay uniform: %+v", step)
	}
	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 44, SessionID: 2, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail || step.ServerMsg != "" {
		t.Fatalf("PAP expired+flag must be uniform FAIL: %+v", step)
	}
}

func TestMustChangeDisabledUniform(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	rev := mgr.Revision()
	if _, err := mgr.UpdateUser("lab-admin", state.UpdateUser{Enabled: boolPtr(false), MustChangeLogin: boolPtr(true)}, &rev); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(45, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(45, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.ServerMsg == promptNewPass {
		t.Fatal("disabled+flag must not prompt New Password")
	}
}

func TestMustChangeRestrictedUniform(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	rev := mgr.Revision()
	if _, err := mgr.UpdateUser("lab-admin", state.UpdateUser{
		MustChangeLogin: boolPtr(true),
		Restrictions:    &config.UserRestrictions{ClientIDs: []string{"lab-switches"}},
	}, &rev); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	start := asciiLoginStart(46, 1)
	start.ClientID = ""
	if _, err := svc.BeginAuthentication(ctx, start); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 46, SessionID: 1, UserMsg: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.ServerMsg == promptNewPass {
		t.Fatal("restricted+flag must not prompt New Password")
	}
}

func TestASCIILoginMustChangeAbort(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(47, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(47, 1, testPassword)); err != nil {
		t.Fatal(err)
	}
	if err := svc.AbortAuthentication(ctx, AuthenticationAbort{ConnKey: 47, SessionID: 1, ClientID: "lab-switches"}); err != nil {
		t.Fatal(err)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if !u.User.MustChangeLogin || u.User.Credentials.Login.Verifier.MemoryID != "" {
		t.Fatal("abort must not publish")
	}
}

func TestASCIILoginMustChangeMismatchFails(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(48, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(48, 1, testPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(48, 1, "new-a")); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(48, 1, "new-b"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("mismatch=%s", step.Status)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if !u.User.MustChangeLogin {
		t.Fatal("mismatch must not clear flag")
	}
}

func TestASCIILoginMustChangeNewEqualsOldAllowed(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(49, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(49, 1, testPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(49, 1, testPassword)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(49, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("new==old=%s", step.Status)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if u.User.MustChangeLogin {
		t.Fatal("flag must clear even when new==old")
	}
}

func TestASCIILoginMustChangeWhenCHPASSDisallowed(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	rev := mgr.Revision()
	auth := config.ClientAuth{AllowedMethods: []config.AuthMethod{config.AuthMethodASCII, config.AuthMethodPAP}}
	if _, err := mgr.UpdateClient("lab-switches", state.UpdateClient{Authentication: &auth}, &rev); err != nil {
		t.Fatal(err)
	}
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(50, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(50, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail || step.ServerMsg != serverMsgPasswordChangeRequired {
		t.Fatalf("K13=%+v", step)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if !u.User.MustChangeLogin || u.User.Credentials.Login.Verifier.MemoryID != "" {
		t.Fatal("must not OverrideLoginVerifier")
	}
}

func TestASCIILoginMustChangeWhenCHPASSAllowed(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	rev := mgr.Revision()
	auth := config.ClientAuth{AllowedMethods: nil}
	if _, err := mgr.UpdateClient("lab-switches", state.UpdateClient{Authentication: &auth}, &rev); err != nil {
		t.Fatal(err)
	}
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(51, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(51, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.ServerMsg != promptNewPass {
		t.Fatalf("empty allow-list must enter GETPASS: %+v", step)
	}
}

func TestCHPASSClearsMustChangeLogin(t *testing.T) {
	t.Parallel()
	svc, mgr, ring := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	const next = "newpass-ok1!"
	if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 52, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(52, 1, testPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(52, 1, next)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(52, 1, next))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("chpass=%s", step.Status)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if u.User.MustChangeLogin {
		t.Fatal("CHPASS must clear flag")
	}
	var saw bool
	for _, ev := range ring.Snapshot() {
		if ev.Type == "ascii_chpass" && ev.Result == "pass" {
			saw = true
			if ev.ReasonCode != reasonPasswordChanged {
				t.Fatalf("reason=%q", ev.ReasonCode)
			}
		}
	}
	if !saw {
		t.Fatal("missing CHPASS pass event")
	}
}

func TestCHPASSPromptsUnchanged(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	step, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 53, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetData || step.ServerMsg != promptPass {
		t.Fatalf("old=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(53, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptPass {
		t.Fatalf("new=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(53, 1, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptPass {
		t.Fatalf("confirm=%+v", step)
	}
}

func TestPAPMustChangeFailsWithServerMsg(t *testing.T) {
	t.Parallel()
	svc, mgr, ring := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 54, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail || step.ServerMsg != serverMsgPasswordChangeRequired {
		t.Fatalf("pap must-change=%+v", step)
	}
	var saw bool
	for _, ev := range ring.Snapshot() {
		if ev.Type == "pap_login" && ev.Result == "fail" && ev.ReasonCode == reasonPasswordChangeRequired {
			saw = true
		}
	}
	if !saw {
		t.Fatal("missing password_change_required event")
	}
}

func TestPAPWrongPasswordEmptyServerMsg(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 55, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte("wrong-password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail || step.ServerMsg != "" {
		t.Fatalf("wrong pap=%+v", step)
	}
}

func TestCHAPMustChangeFailsAfterGoodResponse(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	id := byte(0x42)
	chal := []byte("12345678")
	resp := credentials.CHAPResponse(id, []byte(testChallenge), chal)
	data := append([]byte{id}, append(chal, resp...)...)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 56, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
		Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail || step.ServerMsg != serverMsgPasswordChangeRequired {
		t.Fatalf("chap must-change=%+v", step)
	}
}

func TestMSCHAPMustChangeFailsAfterGoodResponse(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	chal1 := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	resp1 := credentials.MSCHAPv1Response([]byte(testChallenge), chal1, true)
	data1 := append([]byte{9}, append(chal1, resp1...)...)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 57, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeMSCHAP, Service: domain.AuthenServicePPP,
		Data: data1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail || step.ServerMsg != serverMsgPasswordChangeRequired {
		t.Fatalf("mschapv1 must-change=%+v", step)
	}
}

func TestEnableIgnoresMustChangeLogin(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, enableStart(58, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(58, 1, testEnablePW))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("ENABLE must not lock on must_change_login: %+v", step)
	}
	if step.ServerMsg == promptNewPass {
		t.Fatal("must_change_login must not force ENABLE GETPASS")
	}
}

func TestEnableMustChangePromptsAndPass(t *testing.T) {
	t.Parallel()
	svc, mgr, ring := testService(t)
	setMustChangeEnable(t, mgr, "lab-admin", true)
	ctx := context.Background()
	const next = "new-enable-ok1!"
	beforeEvents := len(ring.Snapshot())
	step, err := svc.BeginAuthentication(ctx, enableStart(70, 1))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptPass || !step.NoEcho {
		t.Fatalf("old prompt=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(70, 1, testEnablePW))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptNewPass || !step.NoEcho {
		t.Fatalf("new prompt=%+v", step)
	}
	if n := len(ring.Snapshot()); n != beforeEvents {
		t.Fatalf("no terminal event at extra GETPASS, before=%d after=%d", beforeEvents, n)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(70, 1, next))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptConfirm || !step.NoEcho {
		t.Fatalf("confirm prompt=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(70, 1, next))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("pass=%s", step.Status)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if u.User.MustChangeEnable {
		t.Fatal("flag must clear")
	}
	if u.User.MustChangeLogin {
		t.Fatal("must_change_login must stay false")
	}
	if u.User.Credentials.Login.Verifier.File == "" || u.User.Credentials.Login.Verifier.MemoryID != "" {
		t.Fatalf("login must be untouched: %+v", u.User.Credentials.Login.Verifier)
	}
	if u.User.Credentials.Challenge.Secret.File == "" {
		t.Fatal("challenge must be untouched")
	}
	if u.User.Credentials.Enable.Verifier.MemoryID == "" {
		t.Fatal("enable runtime PHC missing")
	}
	var sawEnable bool
	for _, ev := range ring.Snapshot() {
		if ev.Type == "ascii_chpass" || ev.Type == "ascii_login" {
			t.Fatalf("in-ENABLE must not emit %s: %+v", ev.Type, ev)
		}
		if ev.Type == "enable" && ev.Result == "pass" {
			sawEnable = true
			if ev.ReasonCode != reasonEnablePasswordChanged {
				t.Fatalf("reason=%q", ev.ReasonCode)
			}
		}
	}
	if !sawEnable {
		t.Fatal("missing enable pass event")
	}

	step, err = svc.BeginAuthentication(ctx, enableStart(70, 2))
	if err != nil {
		t.Fatal(err)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(70, 2, next))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("new enable password=%s", step.Status)
	}

	if _, err := svc.BeginAuthentication(ctx, enableStart(70, 3)); err != nil {
		t.Fatal(err)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(70, 3, testEnablePW))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status == domain.AuthenStatusPass {
		t.Fatal("old enable password must not pass after override")
	}

	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 70, SessionID: 4, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("login password must still pass: %s", step.Status)
	}
}

func TestContinueEnableDispatchesNeedNew(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeEnable(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, enableStart(71, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(71, 1, testEnablePW))
	if err != nil {
		t.Fatal(err)
	}
	if step.ServerMsg != promptNewPass {
		t.Fatalf("want New Password, got %+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, continueMsg(71, 1, "brand-new-enable"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptConfirm {
		t.Fatalf("second CONTINUE must confirm, not re-verify: %+v", step)
	}
}

func TestEnableMustChangeLoginDoesNotForceChange(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, enableStart(72, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(72, 1, testEnablePW))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass || step.ServerMsg == promptNewPass {
		t.Fatalf("must_change_login must not force ENABLE change: %+v", step)
	}
}

func TestEnableMustChangeDoesNotBlockLogin(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeEnable(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(73, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(73, 1, testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("must_change_enable must not lock LOGIN: %+v", step)
	}
}

func TestEnableMustChangeWrongPasswordUniform(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeEnable(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, enableStart(74, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(74, 1, "wrong-enable"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || step.ServerMsg != promptPass {
		t.Fatalf("wrong enable must stay uniform GETPASS Password:, got %+v", step)
	}
}

func TestEnableMustChangeWhenOnlyEnableAllowed(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	rev := mgr.Revision()
	auth := config.ClientAuth{AllowedMethods: []config.AuthMethod{config.AuthMethodEnable}}
	if _, err := mgr.UpdateClient("lab-switches", state.UpdateClient{Authentication: &auth}, &rev); err != nil {
		t.Fatal(err)
	}
	setMustChangeEnable(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, enableStart(75, 1)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(75, 1, testEnablePW))
	if err != nil {
		t.Fatal(err)
	}
	if step.ServerMsg != promptNewPass {
		t.Fatalf("in-ENABLE is gated only by enable, got %+v", step)
	}
}

func TestEnableMustChangeAbort(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeEnable(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, enableStart(76, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(76, 1, testEnablePW)); err != nil {
		t.Fatal(err)
	}
	if err := svc.AbortAuthentication(ctx, AuthenticationAbort{ConnKey: 76, SessionID: 1, ClientID: "lab-switches"}); err != nil {
		t.Fatal(err)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if !u.User.MustChangeEnable || u.User.Credentials.Enable.Verifier.MemoryID != "" {
		t.Fatal("abort must not publish")
	}
}

func TestEnableMustChangeMismatchFails(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeEnable(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, enableStart(77, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(77, 1, testEnablePW)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(77, 1, "new-a")); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(77, 1, "new-b"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("mismatch=%s", step.Status)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if !u.User.MustChangeEnable {
		t.Fatal("mismatch must not clear flag")
	}
}

func TestEnableMustChangeRevisionConflict(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeEnable(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, enableStart(78, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(78, 1, testEnablePW)); err != nil {
		t.Fatal(err)
	}
	name := "renamed-enable"
	rev := mgr.Revision()
	if _, err := mgr.UpdateUser("lab-admin", state.UpdateUser{DisplayName: &name}, &rev); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(78, 1, "new-enable-ok1!")); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(78, 1, "new-enable-ok1!"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusError {
		t.Fatalf("revision conflict should ERROR, got %s", step.Status)
	}
}

func TestCHPASSOnEnableStillFailsWithMustChangeEnable(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeEnable(t, mgr, "lab-admin", true)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 79, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceEnable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("CHPASS+ENABLE stays FAIL: %s", step.Status)
	}
}

func TestYAMLMustChangeEnableRestoredAfterChangeAndReset(t *testing.T) {
	t.Parallel()
	_, lookup, mgr := writeSkeletonExtras(t, "    must_change_enable: true\n", "")
	ring := events.New(32, domain.SystemClock{})
	svc, err := New(Options{
		Manager: mgr,
		Secrets: lookup,
		Events:  ring,
		Creds:   credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if !u.User.MustChangeEnable {
		t.Fatal("YAML flag must load on lab-admin")
	}
	ctx := context.Background()
	const next = "new-enable-ok1!"
	if _, err := svc.BeginAuthentication(ctx, enableStart(80, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(80, 1, testEnablePW)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(80, 1, next)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(80, 1, next))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("enable change=%s", step.Status)
	}
	u, _ = mgr.Snapshot().User("lab-admin")
	if u.User.MustChangeEnable {
		t.Fatal("in-ENABLE must clear overlay flag")
	}
	if u.User.Credentials.Enable.Verifier.MemoryID == "" {
		t.Fatal("runtime enable PHC missing")
	}
	rev := mgr.Revision()
	after, err := mgr.Reset(&rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = after.User("lab-admin")
	if !u.User.MustChangeEnable {
		t.Fatal("reset must restore YAML flag")
	}
	if u.User.Credentials.Enable.Verifier.MemoryID != "" || u.User.Credentials.Enable.Verifier.File == "" {
		t.Fatalf("reset must restore YAML enable verifier: %+v", u.User.Credentials.Enable.Verifier)
	}
}

func TestASCIILoginMustChangeRevisionConflict(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	setMustChangeLogin(t, mgr, "lab-admin", true)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, asciiLoginStart(59, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(59, 1, testPassword)); err != nil {
		t.Fatal(err)
	}
	name := "renamed"
	rev := mgr.Revision()
	if _, err := mgr.UpdateUser("lab-admin", state.UpdateUser{DisplayName: &name}, &rev); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(59, 1, "newpass-ok1!")); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(59, 1, "newpass-ok1!"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusError {
		t.Fatalf("revision conflict should ERROR, got %s", step.Status)
	}
}

func TestYAMLMustChangeRestoredAfterCHPASSAndReset(t *testing.T) {
	t.Parallel()
	_, lookup, mgr := writeSkeleton(t, "    must_change_login: true\n")
	ring := events.New(32, domain.SystemClock{})
	svc, err := New(Options{
		Manager: mgr,
		Secrets: lookup,
		Events:  ring,
		Creds:   credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := mgr.Snapshot().User("lab-readonly")
	if !u.User.MustChangeLogin {
		t.Fatal("YAML extra applies to last user; lab-readonly should have the flag")
	}
	ctx := context.Background()
	const next = "newpass-ok1!"
	if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 60, SessionID: 1, UserID: "lab-readonly", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(60, 1, testPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, continueMsg(60, 1, next)); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, continueMsg(60, 1, next))
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("chpass=%s", step.Status)
	}
	u, _ = mgr.Snapshot().User("lab-readonly")
	if u.User.MustChangeLogin {
		t.Fatal("CHPASS must clear overlay flag")
	}
	rev := mgr.Revision()
	after, err := mgr.Reset(&rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = after.User("lab-readonly")
	if !u.User.MustChangeLogin {
		t.Fatal("reset must restore YAML flag")
	}
}

func boolPtr(v bool) *bool { return &v }
