package credentials

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

type secretView interface {
	fmt.Stringer
	fmt.GoStringer
	fmt.Formatter
	json.Marshaler
	Redacted() string
	Bytes() []byte
	Empty() bool
	Len() int
	Purpose() Purpose
}

func TestSecretNonSerialization(t *testing.T) {
	t.Parallel()
	type holder struct {
		name   string
		value  secretView
		canary string
	}

	loginCanary := "unit-test-login-verifier-aa11bb22"
	chapCanary := "unit-test-challenge-secret-cc33dd44"
	enableCanary := "unit-test-enable-verifier-ee55ff66"
	sharedCanary := "unit-test-shared-secret-77889900"
	tokenCanary := "unit-test-token-material-11223344"
	tlsKeyCanary := "unit-test-tls-private-key-55667788"
	tlsPSKCanary := "unit-test-tls-psk-99aabbcc"
	passwordCanary := "unit-test-password-ddeeff00"
	cookieCanary := "unit-test-session-cookie-1234abcd"

	login := NewLoginVerifier([]byte(loginCanary))
	chap := NewChallengeSecret([]byte(chapCanary))
	enable := NewEnableVerifier([]byte(enableCanary))
	shared := NewSharedSecret([]byte(sharedCanary))
	token := NewTokenMaterial([]byte(tokenCanary))
	tlsKey := NewTLSPrivateKey([]byte(tlsKeyCanary))
	tlsPSK := NewTLSPSK([]byte(tlsPSKCanary))
	password := NewPassword([]byte(passwordCanary))
	cookie := NewSessionCookie([]byte(cookieCanary))

	holders := []holder{
		{"LoginVerifier", login, loginCanary},
		{"ChallengeSecret", chap, chapCanary},
		{"EnableVerifier", enable, enableCanary},
		{"SharedSecret", shared, sharedCanary},
		{"TokenMaterial", token, tokenCanary},
		{"TLSPrivateKey", tlsKey, tlsKeyCanary},
		{"TLSPSK", tlsPSK, tlsPSKCanary},
		{"Password", password, passwordCanary},
		{"SessionCookie", cookie, cookieCanary},
	}

	verbs := []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%d"}

	for _, h := range holders {
		h := h
		t.Run(h.name, func(t *testing.T) {
			t.Parallel()
			if h.value.Empty() || h.value.Len() != len(h.canary) {
				t.Fatalf("empty=%v len=%d", h.value.Empty(), h.value.Len())
			}
			if h.value.Redacted() != "[redacted]" {
				t.Fatalf("Redacted=%q", h.value.Redacted())
			}

			for _, verb := range verbs {
				out := fmt.Sprintf(verb, h.value)
				if strings.Contains(out, h.canary) {
					t.Fatalf("fmt %s leaked canary: %q", verb, out)
				}
			}

			wrapped := fmt.Sprintf("holder=%v extra=%#v", h.value, struct{ S secretView }{h.value})
			if strings.Contains(wrapped, h.canary) {
				t.Fatalf("wrapped fmt leaked: %q", wrapped)
			}

			errStr := fmt.Errorf("verify failed: %v", h.value).Error()
			if strings.Contains(errStr, h.canary) {
				t.Fatalf("error string leaked: %q", errStr)
			}

			raw, err := json.Marshal(h.value)
			if err == nil {
				t.Fatal("json.Marshal of secret must fail")
			}
			if strings.Contains(err.Error(), h.canary) {
				t.Fatalf("json error leaked: %v", err)
			}
			if bytes.Contains(raw, []byte(h.canary)) {
				t.Fatalf("json output leaked: %q", raw)
			}

			type envelope struct {
				Secret secretView `json:"secret"`
			}
			raw, err = json.Marshal(envelope{Secret: h.value})
			if err == nil {
				t.Fatal("json.Marshal of envelope must fail")
			}
			if strings.Contains(err.Error(), h.canary) || bytes.Contains(raw, []byte(h.canary)) {
				t.Fatalf("envelope leaked: err=%v raw=%q", err, raw)
			}

			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			log.Info("credential", "secret", h.value)
			if strings.Contains(buf.String(), h.canary) {
				t.Fatalf("slog leaked: %q", buf.String())
			}

			cp := h.value.Bytes()
			if string(cp) != h.canary {
				t.Fatalf("Bytes()=%q", cp)
			}
			cp[0] ^= 0xff
			if string(h.value.Bytes()) != h.canary {
				t.Fatal("Bytes() must copy")
			}
		})
	}
}

func TestSecretConstructorsCopyInput(t *testing.T) {
	t.Parallel()
	in := []byte("unit-test-shared-secret-copy-check")
	s := NewSharedSecret(in)
	in[0] = 'X'
	if string(s.Bytes()) == string(in) {
		t.Fatal("constructor must copy")
	}
}

func TestSecretWipe(t *testing.T) {
	t.Parallel()
	canary := "unit-test-wipe-canary-zzzz1111"
	s := NewPassword([]byte(canary))
	s.Wipe()
	if !s.Empty() || s.Len() != 0 || s.Bytes() != nil {
		t.Fatalf("after wipe: empty=%v len=%d bytes=%q", s.Empty(), s.Len(), s.Bytes())
	}
	if strings.Contains(fmt.Sprintf("%#v", s), canary) {
		t.Fatal("wiped secret still formats canary")
	}
}

func TestSecretEqual(t *testing.T) {
	t.Parallel()
	a := NewLoginVerifier([]byte("same-verifier-material"))
	b := NewLoginVerifier([]byte("same-verifier-material"))
	c := NewLoginVerifier([]byte("other-verifier-material"))
	if !a.Equal(b) {
		t.Fatal("expected equal")
	}
	if a.Equal(c) {
		t.Fatal("expected not equal")
	}
}

func TestSecretPurposes(t *testing.T) {
	t.Parallel()
	if NewLoginVerifier(nil).Purpose() != PurposeLoginVerifier {
		t.Fatal("login")
	}
	if NewChallengeSecret(nil).Purpose() != PurposeChallengeSecret {
		t.Fatal("challenge")
	}
	if NewEnableVerifier(nil).Purpose() != PurposeEnableVerifier {
		t.Fatal("enable")
	}
	if NewSharedSecret(nil).Purpose() != PurposeLegacySharedSecret {
		t.Fatal("shared")
	}
	if NewTokenMaterial(nil).Purpose() != PurposeAPIBearerToken {
		t.Fatal("token")
	}
	if NewTLSPrivateKey(nil).Purpose() != PurposeTLSPrivateKey {
		t.Fatal("tls key")
	}
	if NewTLSPSK(nil).Purpose() != PurposeTLSPSK {
		t.Fatal("tls psk")
	}
	if NewPassword(nil).Purpose() != PurposePassword {
		t.Fatal("password")
	}
	if NewSessionCookie(nil).Purpose() != PurposeSessionCookie {
		t.Fatal("cookie")
	}
}

func TestSecretParentStructFormatting(t *testing.T) {
	t.Parallel()
	canary := "unit-test-parent-fmt-canary-xyz"
	s := NewLoginVerifier([]byte(canary))
	type wrap struct {
		Name string
		Sec  LoginVerifier
	}
	w := wrap{Name: "n", Sec: s}
	for _, out := range []string{
		fmt.Sprintf("%v", w),
		fmt.Sprintf("%+v", w),
		fmt.Sprintf("%#v", w),
		fmt.Sprintf("%#v", &w),
	} {
		if strings.Contains(out, canary) {
			t.Fatalf("parent struct format leaked: %q", out)
		}
	}
	raw, err := json.Marshal(w)
	if err == nil {
		t.Fatal("json.Marshal of parent struct must fail")
	}
	if strings.Contains(err.Error(), canary) || bytes.Contains(raw, []byte(canary)) {
		t.Fatalf("parent json leaked: err=%v raw=%q", err, raw)
	}
}

func TestEmptySecretStillRefusesJSON(t *testing.T) {
	t.Parallel()
	var z LoginVerifier
	if !z.Empty() {
		t.Fatal("zero value")
	}
	if _, err := json.Marshal(z); err == nil {
		t.Fatal("zero value must still refuse JSON")
	}
	if got := fmt.Sprintf("%#v", z); got != "[redacted]" {
		t.Fatalf("zero Go-syntax format = %q", got)
	}
}
