package credentials

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestArgon2idRoundTrip(t *testing.T) {
	t.Parallel()
	pw := []byte("unit-test-login-password-aa11")
	enc, err := DeriveArgon2id(pw, TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePHC(enc); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(enc, []byte("$argon2id$v=19$m=8,t=1,p=1$")) {
		t.Fatalf("unexpected PHC prefix %q", enc)
	}
	if err := VerifyArgon2id(enc, pw); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArgon2id(enc, []byte("wrong-password")); err == nil {
		t.Fatal("wrong password must fail")
	}
}

func TestArgon2idMatchesXCryptoDirect(t *testing.T) {
	t.Parallel()
	// Independent of encodePHC: compute IDKey and compare the PHC hash field.
	password := []byte("password")
	salt := []byte("somesalt") // 8 bytes
	p := Argon2Params{Time: 2, Memory: 32, Threads: 1, SaltLen: 8, KeyLen: 32}
	want := argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	enc := encodePHC(p, salt, want)
	parts := strings.Split(enc, "$")
	got, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("PHC hash field mismatch")
	}
	if err := VerifyArgon2id([]byte(enc), password); err != nil {
		t.Fatal(err)
	}
}

func TestArgon2idRejectsNonPHC(t *testing.T) {
	t.Parallel()
	for _, enc := range []string{
		"plaintext-password",
		"$argon2i$v=19$m=8,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=16$m=8,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=1,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if err := VerifyArgon2id([]byte(enc), []byte("x")); err == nil {
			t.Fatalf("accepted %q", enc)
		}
	}
}

func TestArgon2idWrongPasswordErrorOmitsSecret(t *testing.T) {
	t.Parallel()
	canary := "unit-test-argon2-canary-zz99"
	enc, err := DeriveArgon2id([]byte("correct"), TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyArgon2id(enc, []byte(canary))
	if err == nil {
		t.Fatal("expected fail")
	}
	assertNoCanary(t, "argon2 verify error", err.Error(), canary)
	assertNoCanary(t, "argon2 verify PHC", err.Error(), string(enc))
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("want ErrFailed, got %v", err)
	}
}
