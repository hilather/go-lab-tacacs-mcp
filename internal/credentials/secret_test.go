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
	MarshalText() ([]byte, error)
	MarshalYAML() (any, error)
}

// canaryEncodings is ASCII plus the decimal and hex dumps fmt uses for []byte.
func canaryEncodings(canary string) []string {
	b := []byte(canary)
	dec := make([]string, len(b))
	hex0x := make([]string, len(b))
	hexBare := make([]string, len(b))
	for i, c := range b {
		dec[i] = fmt.Sprintf("%d", c)
		hex0x[i] = fmt.Sprintf("0x%02x", c)
		hexBare[i] = fmt.Sprintf("%02x", c)
	}
	return []string{
		canary,
		strings.Join(dec, " "),
		strings.Join(dec, ", "),
		"[" + strings.Join(dec, " ") + "]",
		strings.Join(hex0x, ", "),
		strings.Join(hexBare, " "),
		strings.Join(hexBare, ""),
	}
}

func assertNoCanary(t *testing.T, where, out, canary string) {
	t.Helper()
	lower := strings.ToLower(out)
	for _, enc := range canaryEncodings(canary) {
		if enc != "" && strings.Contains(lower, strings.ToLower(enc)) {
			t.Fatalf("%s leaked encoding %q in %q", where, enc, out)
		}
	}
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
	radiusCanary := "unit-test-radius-secret-aabb9911"
	tokenCanary := "unit-test-token-material-11223344"
	tlsKeyCanary := "unit-test-tls-private-key-55667788"
	tlsPSKCanary := "unit-test-tls-psk-99aabbcc"
	passwordCanary := "unit-test-password-ddeeff00"
	cookieCanary := "unit-test-session-cookie-1234abcd"

	login := NewLoginVerifier([]byte(loginCanary))
	chap := NewChallengeSecret([]byte(chapCanary))
	enable := NewEnableVerifier([]byte(enableCanary))
	shared := NewSharedSecret([]byte(sharedCanary))
	radius := NewRADIUSSharedSecret([]byte(radiusCanary))
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
		{"RADIUSSharedSecret", radius, radiusCanary},
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
				assertNoCanary(t, "fmt "+verb, out, h.canary)
			}

			wrapped := fmt.Sprintf("holder=%v extra=%#v", h.value, struct{ S secretView }{h.value})
			assertNoCanary(t, "wrapped fmt", wrapped, h.canary)

			errStr := fmt.Errorf("verify failed: %v", h.value).Error()
			assertNoCanary(t, "error string", errStr, h.canary)

			raw, err := json.Marshal(h.value)
			if err == nil {
				t.Fatal("json.Marshal of secret must fail")
			}
			assertNoCanary(t, "json error", err.Error(), h.canary)
			assertNoCanary(t, "json output", string(raw), h.canary)

			type envelope struct {
				Secret secretView `json:"secret"`
			}
			raw, err = json.Marshal(envelope{Secret: h.value})
			if err == nil {
				t.Fatal("json.Marshal of envelope must fail")
			}
			assertNoCanary(t, "envelope error", err.Error(), h.canary)
			assertNoCanary(t, "envelope output", string(raw), h.canary)

			text, err := h.value.MarshalText()
			if err == nil {
				t.Fatal("MarshalText of secret must fail")
			}
			assertNoCanary(t, "MarshalText error", err.Error(), h.canary)
			assertNoCanary(t, "MarshalText output", string(text), h.canary)

			y, err := h.value.MarshalYAML()
			if err == nil {
				t.Fatal("MarshalYAML of secret must fail")
			}
			assertNoCanary(t, "MarshalYAML error", err.Error(), h.canary)
			if y != nil {
				assertNoCanary(t, "MarshalYAML value", fmt.Sprint(y), h.canary)
			}

			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			log.Info("credential", "secret", h.value)
			assertNoCanary(t, "slog", buf.String(), h.canary)

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
	assertNoCanary(t, "wiped %#v", fmt.Sprintf("%#v", s), canary)
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
	if NewRADIUSSharedSecret(nil).Purpose() != PurposeRADIUSSharedSecret {
		t.Fatal("radius")
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
		assertNoCanary(t, "exported parent fmt", out, canary)
	}
	raw, err := json.Marshal(w)
	if err == nil {
		t.Fatal("json.Marshal of parent struct must fail")
	}
	assertNoCanary(t, "parent json error", err.Error(), canary)
	assertNoCanary(t, "parent json output", string(raw), canary)
}

func TestUnexportedHolderFmtFootgun(t *testing.T) {
	t.Parallel()
	// fmt walks unexported fields without calling Format. Later AAA request
	// types must export holders or log via slog/Redacted — never %+v of req.
	canary := "unit-test-unexported-fmt-canary"
	type req struct {
		sec Password
	}
	out := fmt.Sprintf("%+v", req{sec: NewPassword([]byte(canary))})
	if strings.Contains(out, canary) {
		t.Fatalf("ASCII canary leaked from unexported field: %q", out)
	}
	encs := canaryEncodings(canary)
	decimal, hexDump := encs[1], encs[4]
	if !strings.Contains(out, decimal) && !strings.Contains(strings.ToLower(out), hexDump) {
		t.Fatalf("expected decimal or hex dump of unexported holder (callers must not %%+v this): %q", out)
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
