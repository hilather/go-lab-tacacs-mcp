package credentials

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

type testClock struct{ t time.Time }

func (c testClock) Now() time.Time { return c.t }

func testOpts(c domain.Clock) Options {
	if c == nil {
		c = testClock{t: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)}
	}
	return Options{
		Clock:            c,
		Entropy:          rand.Reader,
		Params:           TestParams,
		MinCHAPChallenge: 8,
		KDFWorkers:       2,
	}
}

func mustService(t *testing.T, recs ...Record) *Service {
	t.Helper()
	st := NewMemory()
	for _, r := range recs {
		st.Put(r)
	}
	s, err := NewService(st, testOpts(nil))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustLogin(t *testing.T, s *Service, pw string) LoginVerifier {
	t.Helper()
	v, err := s.DeriveLoginVerifier(context.Background(), []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustEnable(t *testing.T, s *Service, pw string) EnableVerifier {
	t.Helper()
	v, err := s.DeriveEnableVerifier(context.Background(), []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyASCIIOrPAPCorrectAndWrong(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	login := mustLogin(t, s, "correct-login-secret")
	s.store.(*Memory).Put(Record{ID: "alice", Enabled: true, Login: login})
	if err := s.VerifyASCIIOrPAP(context.Background(), "alice", []byte("correct-login-secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyASCIIOrPAP(context.Background(), "alice", []byte("wrong-login-secret")); err == nil || !errors.Is(err, ErrFailed) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyUniformFailureKinds(t *testing.T) {
	t.Parallel()
	clock := testClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	st := NewMemory()
	s, err := NewService(st, testOpts(clock))
	if err != nil {
		t.Fatal(err)
	}
	login := mustLogin(t, s, "pw")
	after := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	st.Put(Record{ID: "ok", Enabled: true, Login: login})
	st.Put(Record{ID: "off", Enabled: false, Login: login})
	st.Put(Record{ID: "deny", Enabled: true, Restricted: true, Login: login})
	st.Put(Record{ID: "late", Enabled: true, Login: login, ValidAfter: &after})
	st.Put(Record{ID: "gone", Enabled: true, Login: login, ValidBefore: &before})
	st.Put(Record{ID: "nochal", Enabled: true, Login: login})

	cases := []struct {
		user string
		kind FailureKind
	}{
		{"missing-user", KindUnknown},
		{"off", KindDisabled},
		{"deny", KindRestricted},
		{"late", KindExpired},
		{"gone", KindExpired},
	}
	for _, tc := range cases {
		err := s.VerifyASCIIOrPAP(context.Background(), tc.user, []byte("pw"))
		var ae AuthError
		if !errorAsAuth(err, &ae) || ae.Kind != tc.kind {
			t.Fatalf("%s: %+v", tc.user, err)
		}
		if err.Error() != ErrFailed.Error() {
			t.Fatalf("%s message %q", tc.user, err.Error())
		}
	}
	missing := s.VerifyCHAP(context.Background(), "nochal", 1, bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{2}, 16))
	unknown := s.VerifyCHAP(context.Background(), "missing-user", 1, bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{2}, 16))
	var ae AuthError
	if !errorAsAuth(missing, &ae) || ae.Kind != KindMissing {
		t.Fatalf("missing challenge: %v", missing)
	}
	if missing.Error() != unknown.Error() || missing.Error() != ErrFailed.Error() {
		t.Fatalf("unknown vs missing CHAP must share Error() text: %q %q", unknown, missing)
	}
}

func TestLookupIgnoresMustChangeLogin(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	login := mustLogin(t, s, "correct-login-secret")
	before := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	s.store.(*Memory).Put(Record{ID: "force", Enabled: true, Login: login, MustChangeLogin: true})
	s.store.(*Memory).Put(Record{ID: "gone", Enabled: true, Login: login, MustChangeLogin: true, ValidBefore: &before})
	if err := s.VerifyASCIIOrPAP(context.Background(), "force", []byte("correct-login-secret")); err != nil {
		t.Fatalf("must-change must not fail lookup: %v", err)
	}
	err := s.VerifyASCIIOrPAP(context.Background(), "gone", []byte("correct-login-secret"))
	var ae AuthError
	if !errorAsAuth(err, &ae) || ae.Kind != KindExpired {
		t.Fatalf("account window still KindExpired: %v", err)
	}
}

func TestNoFallbackAcrossCredentialClasses(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	login := mustLogin(t, s, "login-only-password")
	enable := mustEnable(t, s, "enable-only-password")
	chal := NewChallengeSecret([]byte("challenge-only-secret"))
	s.store.(*Memory).Put(Record{
		ID:        "split",
		Enabled:   true,
		Login:     login,
		Enable:    enable,
		Challenge: chal,
	})
	ctx := context.Background()
	if err := s.VerifyEnable(ctx, "split", []byte("login-only-password")); err == nil {
		t.Fatal("ENABLE must not accept login password")
	}
	if err := s.VerifyASCIIOrPAP(ctx, "split", []byte("enable-only-password")); err == nil {
		t.Fatal("login must not accept ENABLE password")
	}
	if err := s.VerifyEnable(ctx, "split", []byte("enable-only-password")); err != nil {
		t.Fatal(err)
	}
	// Login verifier must not satisfy CHAP.
	s.store.(*Memory).Put(Record{ID: "ascii-only", Enabled: true, Login: login})
	resp := CHAPResponse(1, []byte("login-only-password"), bytes.Repeat([]byte{'c'}, 8))
	err := s.VerifyCHAP(ctx, "ascii-only", 1, bytes.Repeat([]byte{'c'}, 8), resp)
	var ae AuthError
	if !errorAsAuth(err, &ae) || ae.Kind != KindMissing || !errors.Is(err, ErrFailed) {
		t.Fatalf("CHAP without challenge secret: %v", err)
	}
}

func TestChangeASCIIPasswordDoesNotTouchChallenge(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	login := mustLogin(t, s, "old-pass")
	chal := NewChallengeSecret([]byte("stay-the-same"))
	mem := s.store.(*Memory)
	mem.Put(Record{ID: "bob", Enabled: true, Login: login, Challenge: chal})
	ctx := context.Background()
	enc, err := s.ChangeASCIIPassword(ctx, "bob", []byte("old-pass"), []byte("new-pass"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("new-pass")) || bytes.Contains(enc, []byte("old-pass")) {
		t.Fatal("PHC must not contain plaintext")
	}
	// Store still has old login until the caller publishes.
	if err := s.VerifyASCIIOrPAP(ctx, "bob", []byte("old-pass")); err != nil {
		t.Fatal(err)
	}
	cur, _ := mem.Lookup("bob")
	cur.Login = NewLoginVerifier(enc)
	mem.Put(cur)
	if err := s.VerifyASCIIOrPAP(ctx, "bob", []byte("new-pass")); err != nil {
		t.Fatal(err)
	}
	got, _ := mem.Lookup("bob")
	if !got.Challenge.Equal(chal) {
		t.Fatal("challenge secret changed")
	}
	resp := CHAPResponse(2, []byte("stay-the-same"), bytes.Repeat([]byte{9}, 8))
	if err := s.VerifyCHAP(ctx, "bob", 2, bytes.Repeat([]byte{9}, 8), resp); err != nil {
		t.Fatal(err)
	}
}

func TestChangeASCIIPasswordRejectsWrongOld(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	login := mustLogin(t, s, "old-pass")
	s.store.(*Memory).Put(Record{ID: "bob", Enabled: true, Login: login})
	_, err := s.ChangeASCIIPassword(context.Background(), "bob", []byte("nope"), []byte("new-pass"))
	if err == nil || !errors.Is(err, ErrFailed) {
		t.Fatalf("got %v", err)
	}
}

func TestServiceCHAPAndMSCHAPVectors(t *testing.T) {
	t.Parallel()
	v := loadVectors(t)
	s := mustService(t)
	mem := s.store.(*Memory)
	ctx := context.Background()

	mem.Put(Record{ID: "chap-user", Enabled: true, Challenge: NewChallengeSecret([]byte(v.CHAP[0].Secret))})
	chal := mustHex(t, v.CHAP[0].ChallengeHex)
	resp := mustHex(t, v.CHAP[0].ResponseHex)
	if err := s.VerifyCHAP(ctx, "chap-user", v.CHAP[0].ID, chal, resp); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyCHAP(ctx, "chap-user", v.CHAP[1].ID, chal, resp); err == nil {
		t.Fatal("wrong PPP id must fail CHAP")
	}

	mem.Put(Record{ID: "User", Enabled: true, Challenge: NewChallengeSecret([]byte(v.MSCHAPv2.Password))})
	auth := mustHex(t, v.MSCHAPv2.ChallengeHex)
	peer := mustHex(t, v.MSCHAPv2.PeerChallengeHex)
	v2 := MSCHAPv2Response([]byte(v.MSCHAPv2.Password), []byte("User"), auth, peer)
	if err := s.VerifyMSCHAPv2(ctx, "User", 1, auth, v2); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyMSCHAPv2(ctx, "User", 2, auth, v2); err != nil {
		t.Fatal(err)
	}

	v1chal := mustHex(t, v.MSCHAPv1.ChallengeHex)
	v1 := MSCHAPv1Response([]byte(v.MSCHAPv1.Password), v1chal, true)
	if err := s.VerifyMSCHAPv1(ctx, "User", 1, v1chal, v1); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyMSCHAPv1(ctx, "User", 2, v1chal, v1); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilitiesOmitSecrets(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	s.store.(*Memory).Put(Record{
		ID:        "c",
		Enabled:   true,
		Login:     mustLogin(t, s, "x"),
		Challenge: NewChallengeSecret([]byte("chal")),
	})
	caps := s.Capabilities("c")
	if !caps.Login || !caps.Challenge || caps.Enable {
		t.Fatalf("%+v", caps)
	}
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "chal") {
		t.Fatalf("caps json leaked: %s", raw)
	}
	if s.Capabilities("missing") != (Capabilities{}) {
		t.Fatal("unknown user caps")
	}
}

func TestMSCHAPv2MalformedIndependentOfUser(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	login := mustLogin(t, s, "pw")
	s.store.(*Memory).Put(Record{ID: "ascii-only", Enabled: true, Login: login})
	s.store.(*Memory).Put(Record{ID: "chal", Enabled: true, Challenge: NewChallengeSecret([]byte("challenge-secret"))})
	ctx := context.Background()
	chal := make([]byte, 16)
	reserved := make([]byte, 49)
	reserved[20] = 1
	flags := make([]byte, 49)
	flags[48] = 1
	users := []string{"missing-user", "ascii-only", "chal"}
	for _, user := range users {
		if err := s.VerifyMSCHAPv2(ctx, user, 1, chal, reserved); !errors.Is(err, ErrMalformed) {
			t.Fatalf("reserved %s: %v", user, err)
		}
		if err := s.VerifyMSCHAPv2(ctx, user, 1, chal, flags); !errors.Is(err, ErrMalformed) {
			t.Fatalf("flags %s: %v", user, err)
		}
	}
}

func TestServiceCHAPMalformedLengths(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	s.store.(*Memory).Put(Record{ID: "u", Enabled: true, Challenge: NewChallengeSecret([]byte("s"))})
	if err := s.VerifyCHAP(context.Background(), "u", 1, []byte("123"), make([]byte, 16)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
	if err := s.VerifyMSCHAPv1(context.Background(), "u", 1, make([]byte, 7), make([]byte, 49)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
	if err := s.VerifyMSCHAPv2(context.Background(), "u", 1, make([]byte, 16), make([]byte, 40)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
}

func TestMemoryStoreClonesMaterial(t *testing.T) {
	t.Parallel()
	st := NewMemory()
	login := NewLoginVerifier([]byte("$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	st.Put(Record{ID: "z", Enabled: true, Login: login})
	login.Wipe()
	got, ok := st.Lookup("z")
	if !ok || got.Login.Empty() {
		t.Fatal("store must keep its own copy")
	}
}

func TestUsernameCanonicalLookup(t *testing.T) {
	t.Parallel()
	s := mustService(t)
	login := mustLogin(t, s, "pw")
	id, err := CanonicalUsername("LabUser")
	if err != nil {
		t.Fatal(err)
	}
	s.store.(*Memory).Put(Record{ID: id, Enabled: true, Login: login})
	if err := s.VerifyASCIIOrPAP(context.Background(), "LabUser", []byte("pw")); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentVerify(t *testing.T) {
	s := mustService(t)
	login := mustLogin(t, s, "pw")
	s.store.(*Memory).Put(Record{
		ID:        "race",
		Enabled:   true,
		Login:     login,
		Challenge: NewChallengeSecret([]byte("chal")),
	})
	ctx := context.Background()
	chal := bytes.Repeat([]byte{3}, 8)
	resp := CHAPResponse(4, []byte("chal"), chal)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.VerifyASCIIOrPAP(ctx, "race", []byte("pw")); err != nil {
				t.Errorf("ascii: %v", err)
			}
			if err := s.VerifyCHAP(ctx, "race", 4, chal, resp); err != nil {
				t.Errorf("chap: %v", err)
			}
		}()
	}
	wg.Wait()
}
