package aaa

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

func TestPAPLoginPassAndFail(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	ctx := context.Background()
	step, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 10, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("pap pass=%s", step.Status)
	}
	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 10, SessionID: 2, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte("wrong-password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("pap wrong=%s", step.Status)
	}
	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 10, SessionID: 3, UserID: "no-such-user", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("pap unknown=%s", step.Status)
	}
	for _, ev := range ring.Snapshot() {
		if ev.Category == "authen" && ev.Type == "pap_login" && bytes.Contains([]byte(ev.UserID+ev.Result), []byte(testPassword)) {
			t.Fatalf("password leaked in event: %+v", ev)
		}
	}
}

func TestPAPMissingUserOrDataFails(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	for _, start := range []AuthenticationStart{
		{ConnKey: 11, SessionID: 1, ClientID: "lab-switches", Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin, Data: []byte(testPassword)},
		{ConnKey: 11, SessionID: 2, UserID: "lab-admin", ClientID: "lab-switches", Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin},
	} {
		step, err := svc.BeginAuthentication(ctx, start)
		if err != nil {
			t.Fatal(err)
		}
		if step.Status != domain.AuthenStatusFail {
			t.Fatalf("start=%+v status=%s", start, step.Status)
		}
	}
}

func TestASCIIIgnoresStartData(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	step, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 12, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
		Data: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass {
		t.Fatalf("status=%s", step.Status)
	}
	step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 12, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("pass=%s", step.Status)
	}
}

func TestCHAPLoginIndependentVector(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	id := byte(0x42)
	chal := []byte("12345678")
	resp := credentials.CHAPResponse(id, []byte(testChallenge), chal)
	data := append([]byte{id}, append(chal, resp...)...)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 13, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
		Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("chap pass=%s", step.Status)
	}

	bad := append([]byte{id}, append(chal, bytes.Repeat([]byte{0}, 16)...)...)
	step, err = svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 13, SessionID: 2, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
		Data: bad,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("chap wrong=%s", step.Status)
	}
}

func TestCHAPMalformedIsError(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 14, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
		Data: []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusError {
		t.Fatalf("malformed chap=%s", step.Status)
	}
}

func TestCHAPBelowMinimumChallengeErrors(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	id := byte(1)
	chal := []byte("1234567") // 7 < 8
	resp := credentials.CHAPResponse(id, []byte(testChallenge), chal)
	data := append([]byte{id}, append(chal, resp...)...)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 15, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
		Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusError {
		t.Fatalf("short challenge=%s", step.Status)
	}
}

func TestCHAPNoFallbackToLoginHash(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	id := byte(1)
	chal := []byte("12345678")
	resp := credentials.CHAPResponse(id, []byte(testPassword), chal)
	data := append([]byte{id}, append(chal, resp...)...)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 16, SessionID: 1, UserID: "lab-readonly", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeCHAP, Service: domain.AuthenServicePPP,
		Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("readonly has no challenge secret, want FAIL got %s", step.Status)
	}
}

func TestMSCHAPv1AndV2Vectors(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	chal1 := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	resp1 := credentials.MSCHAPv1Response([]byte(testChallenge), chal1, true)
	data1 := append([]byte{9}, append(chal1, resp1...)...)
	step, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 17, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeMSCHAP, Service: domain.AuthenServicePPP,
		Data: data1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("mschapv1=%s", step.Status)
	}

	authCh := mustHex(t, "5b5d7c7d7b3f2f3e3c2c602132262628")
	peer := mustHex(t, "21402324255e262a28295f2b3a337c7e")
	resp2 := credentials.MSCHAPv2Response([]byte(testChallenge), []byte("lab-admin"), authCh, peer)
	data2 := append([]byte{17}, append(authCh, resp2...)...)
	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 17, SessionID: 2, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeMSCHAPV2, Service: domain.AuthenServicePPP,
		Data: data2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("mschapv2=%s", step.Status)
	}

	short := append([]byte{9}, chal1...)
	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 17, SessionID: 3, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeMSCHAP, Service: domain.AuthenServicePPP,
		Data: short,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusError {
		t.Fatalf("mschapv1 short=%s", step.Status)
	}
}

func TestEnableIgnoresTypeGoldens(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	for i, name := range []string{"authen-start-enable-ascii.bin", "authen-start-enable-pap.bin"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "protocol", "bodies", name))
		if err != nil {
			t.Fatal(err)
		}
		st, err := codec.DecodeAuthenStart(raw)
		if err != nil {
			t.Fatal(err)
		}
		if st.Service != codec.AuthenServiceEnable {
			t.Fatalf("%s service=%d", name, st.Service)
		}
		step, err := svc.BeginAuthentication(ctx, AuthenticationStart{
			ConnKey: 18, SessionID: uint32(i + 1), UserID: "lab-admin", ClientID: "lab-switches",
			Action: domain.AuthenAction(st.Action), Type: domain.AuthenType(st.Type),
			Service: domain.AuthenService(st.Service), PrivLvl: st.PrivLvl,
		})
		if err != nil {
			t.Fatal(err)
		}
		if step.Status != domain.AuthenStatusGetPass || !step.NoEcho {
			t.Fatalf("%s did not enter ENABLE (status=%s)", name, step.Status)
		}
		step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
			ConnKey: 18, SessionID: uint32(i + 1), UserMsg: []byte(testEnablePW), ClientID: "lab-switches",
		})
		if err != nil {
			t.Fatal(err)
		}
		if step.Status != domain.AuthenStatusPass {
			t.Fatalf("%s enable pass=%s", name, step.Status)
		}
	}
}

func TestEnableWrongAndMissingVerifier(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 19, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceEnable,
	}); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 19, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass {
		t.Fatalf("login password must not satisfy ENABLE: %s", step.Status)
	}

	if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 19, SessionID: 2, UserID: "lab-readonly", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceEnable,
	}); err != nil {
		t.Fatal(err)
	}
	var last AuthenticationStep
	for i := 0; i < 16; i++ {
		last, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
			ConnKey: 19, SessionID: 2, UserMsg: []byte(testEnablePW), ClientID: "lab-switches",
		})
		if err != nil {
			t.Fatal(err)
		}
		if last.Status == domain.AuthenStatusFail {
			break
		}
	}
	if last.Status != domain.AuthenStatusFail {
		t.Fatalf("missing enable verifier terminal=%s", last.Status)
	}
}

func TestCHPASSChangeAndReset(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	ctx := context.Background()
	const next = "newpass-ok1!"
	if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 20, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 20, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || !step.NoEcho {
		t.Fatalf("old password must GETDATA then new GETPASS, after old got %s", step.Status)
	}
	// The first CONTINUE after START with user is GETDATA (old). We already sent old.
	// begin with user present starts at GETDATA. continue old → GETPASS (new).
	if step.Status != domain.AuthenStatusGetPass {
		t.Fatalf("new password prompt=%s", step.Status)
	}
	step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 20, SessionID: 1, UserMsg: []byte(next), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass {
		t.Fatalf("confirm prompt=%s", step.Status)
	}
	step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 20, SessionID: 1, UserMsg: []byte(next), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("chpass pass=%s", step.Status)
	}
	u, ok := mgr.Snapshot().User("lab-admin")
	if !ok || u.User.Credentials.Login.Verifier.MemoryID == "" {
		t.Fatal("runtime login override missing")
	}
	if u.User.Credentials.Challenge.Secret.File == "" {
		t.Fatal("challenge secret must be unchanged")
	}

	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 20, SessionID: 2, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(next),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("new password pap=%s", step.Status)
	}
	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 20, SessionID: 3, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("old password after chpass=%s", step.Status)
	}

	rev := mgr.Revision()
	if _, err := mgr.Reset(&rev); err != nil {
		t.Fatal(err)
	}
	step, err = svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 20, SessionID: 4, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin,
		Data: []byte(testPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusPass {
		t.Fatalf("reset restores baseline password: %s", step.Status)
	}
}

func TestCHPASSOldIsGetDataNewIsGetPass(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	step, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 21, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetData || !step.NoEcho {
		t.Fatalf("old=%+v", step)
	}
	step, err = svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 21, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusGetPass || !step.NoEcho {
		t.Fatalf("new=%+v", step)
	}
}

func TestCHPASSMismatchAndAbort(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	ctx := context.Background()
	start := AuthenticationStart{
		ConnKey: 22, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}
	if _, err := svc.BeginAuthentication(ctx, start); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 22, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 22, SessionID: 1, UserMsg: []byte("new-a"), ClientID: "lab-switches",
	}); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 22, SessionID: 1, UserMsg: []byte("new-b"), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("mismatch=%s", step.Status)
	}

	if _, err := svc.BeginAuthentication(ctx, start); err != nil {
		t.Fatal(err)
	}
	if err := svc.AbortAuthentication(ctx, AuthenticationAbort{ConnKey: 22, SessionID: 1, ClientID: "lab-switches"}); err != nil {
		t.Fatal(err)
	}
	if svc.InFlight() != 0 {
		t.Fatalf("inflight=%d", svc.InFlight())
	}
	u, _ := mgr.Snapshot().User("lab-admin")
	if u.User.Credentials.Login.Verifier.MemoryID != "" {
		t.Fatal("abort must not publish an override")
	}
}

func TestCHPASSRevisionConflict(t *testing.T) {
	t.Parallel()
	svc, mgr, _ := testService(t)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 27, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}); err != nil {
		t.Fatal(err)
	}
	name := "renamed"
	rev := mgr.Revision()
	if _, err := mgr.UpdateUser("lab-admin", state.UpdateUser{DisplayName: &name}, &rev); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 27, SessionID: 1, UserMsg: []byte(testPassword), ClientID: "lab-switches",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 27, SessionID: 1, UserMsg: []byte("newpass-ok1!"), ClientID: "lab-switches",
	}); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 27, SessionID: 1, UserMsg: []byte("newpass-ok1!"), ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusError {
		t.Fatalf("revision conflict should ERROR, got %s", step.Status)
	}
}

func TestCHPASSOnEnableServiceFails(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 23, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceEnable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("chpass+enable=%s", step.Status)
	}
}

func TestChallengeOnlyRestartsNonChallenge(t *testing.T) {
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
    authentication: {allowed_methods: [chap, mschapv1, mschapv2]}
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
	svc, err := New(Options{Manager: mgr, Secrets: lookup, Creds: credentials.Options{Params: credentials.TestParams}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i, start := range []AuthenticationStart{
		{Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin},
		{Action: domain.AuthenActionLogin, Type: domain.AuthenTypePAP, Service: domain.AuthenServiceLogin, UserID: "u", Data: []byte("x")},
		{Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceEnable},
		{Action: domain.AuthenActionCHPASS, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin},
	} {
		start.ConnKey = 24
		start.SessionID = uint32(i + 1)
		start.ClientID = "chap-only"
		step, err := svc.BeginAuthentication(ctx, start)
		if err != nil {
			t.Fatal(err)
		}
		if step.Status != domain.AuthenStatusRestart {
			t.Fatalf("%+v status=%s", start, step.Status)
		}
	}
}

func TestContinueAbortIsNotPass(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	ctx := context.Background()
	if _, err := svc.BeginAuthentication(ctx, AuthenticationStart{
		ConnKey: 25, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceLogin,
	}); err != nil {
		t.Fatal(err)
	}
	step, err := svc.ContinueAuthentication(ctx, AuthenticationContinue{
		ConnKey: 25, SessionID: 1, Abort: true, ClientID: "lab-switches",
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status == domain.AuthenStatusPass {
		t.Fatal("abort reply must not be PASS")
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("abort=%s", step.Status)
	}
}

func TestInvalidServiceFails(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	step, err := svc.BeginAuthentication(context.Background(), AuthenticationStart{
		ConnKey: 26, SessionID: 1, UserID: "lab-admin", ClientID: "lab-switches",
		Action: domain.AuthenActionLogin, Type: domain.AuthenTypeASCII, Service: domain.AuthenServiceNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != domain.AuthenStatusFail {
		t.Fatalf("none service=%s", step.Status)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
