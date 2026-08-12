package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestVerifyErrorsNeverContainSecrets(t *testing.T) {
	t.Parallel()
	loginCanary := "unit-test-login-canary-verify-aa11"
	chapCanary := "unit-test-chap-canary-verify-bb22"
	enableCanary := "unit-test-enable-canary-verify-cc33"
	mschapCanary := "unit-test-mschap-canary-verify-dd44"
	tokenCanary := "unit-test-token-canary-verify-ee55"

	s := mustService(t)
	login := mustLogin(t, s, "real-login")
	enable := mustEnable(t, s, "real-enable")
	s.store.(*Memory).Put(Record{
		ID:        "canary",
		Enabled:   true,
		Login:     login,
		Enable:    enable,
		Challenge: NewChallengeSecret([]byte(chapCanary)),
	})
	ctx := context.Background()

	errs := []error{
		s.VerifyASCIIOrPAP(ctx, "canary", []byte(loginCanary)),
		s.VerifyEnable(ctx, "canary", []byte(enableCanary)),
		s.VerifyCHAP(ctx, "canary", 1, bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{2}, 16)),
		s.VerifyMSCHAPv1(ctx, "canary", 1, bytes.Repeat([]byte{3}, 8), append(bytes.Repeat([]byte{4}, 48), 1)),
		s.VerifyMSCHAPv2(ctx, "canary", 1, bytes.Repeat([]byte{5}, 16), append(bytes.Repeat([]byte{6}, 48), 0)),
	}
	_, cherr := s.ChangeASCIIPassword(ctx, "canary", []byte(loginCanary), []byte("unit-test-new-password-ff66"))
	errs = append(errs, cherr)

	canaries := []string{loginCanary, chapCanary, enableCanary, mschapCanary, tokenCanary, "real-login", "real-enable", "unit-test-new-password-ff66"}
	for i, err := range errs {
		if err == nil {
			t.Fatalf("case %d: expected error", i)
		}
		msg := err.Error()
		wrapped := fmt.Sprintf("%v %#v %s", err, err, msg)
		for _, c := range canaries {
			assertNoCanary(t, fmt.Sprintf("verify[%d]", i), wrapped, c)
		}
		raw, jerr := json.Marshal(struct{ E string }{E: msg})
		if jerr != nil {
			t.Fatal(jerr)
		}
		for _, c := range canaries {
			assertNoCanary(t, fmt.Sprintf("json[%d]", i), string(raw), c)
		}
	}

	tok := NewTokenMaterial([]byte(tokenCanary))
	d := DigestToken(tok)
	if out := fmt.Sprintf("%v %s %#v", tok, d, d); bytes.Contains([]byte(out), []byte(tokenCanary)) {
		t.Fatalf("token leaked: %q", out)
	}
}
