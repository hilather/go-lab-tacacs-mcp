package credentials

import (
	"context"
	"crypto/rand"
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Verifier is the protocol-independent credential surface (canonical design).
type Verifier interface {
	VerifyASCIIOrPAP(ctx context.Context, userID string, password []byte) error
	VerifyCHAP(ctx context.Context, userID string, id byte, challenge, response []byte) error
	VerifyMSCHAPv1(ctx context.Context, userID string, id byte, challenge, response []byte) error
	VerifyMSCHAPv2(ctx context.Context, userID string, id byte, challenge, response []byte) error
	VerifyEnable(ctx context.Context, userID string, secret []byte) error
	ChangeASCIIPassword(ctx context.Context, userID string, old, new []byte) (runtimeVerifier []byte, err error)
}

// Options configures encode-time KDF, challenge policy, and injectables.
type Options struct {
	Clock            domain.Clock
	Entropy          domain.Entropy
	Params           Argon2Params
	MinCHAPChallenge int
	KDFWorkers       int
}

// Service verifies credentials against a Store. It is safe for concurrent use.
type Service struct {
	store      Store
	clock      domain.Clock
	entropy    io.Reader
	params     Argon2Params
	minCHAP    int
	kdf        chan struct{}
	dummyLogin []byte
	dummyChal  []byte
}

// NewService builds a Service. Zero Options select ADR-0002 defaults.
func NewService(store Store, opts Options) (*Service, error) {
	if store == nil {
		return nil, invalidMaterial()
	}
	if opts.Clock == nil {
		opts.Clock = domain.SystemClock{}
	}
	if opts.Entropy == nil {
		opts.Entropy = rand.Reader
	}
	if opts.Params == (Argon2Params{}) {
		opts.Params = DefaultParams
	}
	if err := opts.Params.validEncode(); err != nil {
		return nil, err
	}
	if opts.MinCHAPChallenge <= 0 {
		opts.MinCHAPChallenge = DefaultMinCHAPChallenge
	}
	if opts.KDFWorkers <= 0 {
		opts.KDFWorkers = 2
	}
	s := &Service{
		store:   store,
		clock:   opts.Clock,
		entropy: opts.Entropy,
		params:  opts.Params,
		minCHAP: opts.MinCHAPChallenge,
		kdf:     make(chan struct{}, opts.KDFWorkers),
	}
	dummyPW := make([]byte, 16)
	if _, err := io.ReadFull(opts.Entropy, dummyPW); err != nil {
		return nil, err
	}
	enc, err := DeriveArgon2id(dummyPW, opts.Params, opts.Entropy)
	wipeBytes(dummyPW)
	if err != nil {
		return nil, err
	}
	s.dummyLogin = enc
	s.dummyChal = make([]byte, 16)
	if _, err := io.ReadFull(opts.Entropy, s.dummyChal); err != nil {
		return nil, err
	}
	return s, nil
}

var _ Verifier = (*Service)(nil)

// DeriveLoginVerifier hashes a runtime plaintext password. password is
// caller-owned and is not wiped.
func (s *Service) DeriveLoginVerifier(ctx context.Context, password []byte) (LoginVerifier, error) {
	if err := ctx.Err(); err != nil {
		return LoginVerifier{}, err
	}
	if err := s.acquireKDF(ctx); err != nil {
		return LoginVerifier{}, err
	}
	defer s.releaseKDF()
	enc, err := DeriveArgon2id(password, s.params, s.entropy)
	if err != nil {
		return LoginVerifier{}, err
	}
	return NewLoginVerifier(enc), nil
}

// DeriveEnableVerifier hashes a runtime ENABLE password. It never writes login
// or challenge material.
func (s *Service) DeriveEnableVerifier(ctx context.Context, password []byte) (EnableVerifier, error) {
	if err := ctx.Err(); err != nil {
		return EnableVerifier{}, err
	}
	if err := s.acquireKDF(ctx); err != nil {
		return EnableVerifier{}, err
	}
	defer s.releaseKDF()
	enc, err := DeriveArgon2id(password, s.params, s.entropy)
	if err != nil {
		return EnableVerifier{}, err
	}
	return NewEnableVerifier(enc), nil
}

// Capabilities returns secret-free method presence for a canonical user id.
func (s *Service) Capabilities(userID string) Capabilities {
	rec, err := s.lookup(userID)
	if err != nil {
		return Capabilities{}
	}
	return rec.Caps()
}

// VerifyASCIIOrPAP checks password against the user's login Argon2id verifier.
// password is caller-owned and is not wiped.
func (s *Service) VerifyASCIIOrPAP(ctx context.Context, userID string, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, lerr := s.lookup(userID)
	if err := s.acquireKDF(ctx); err != nil {
		return err
	}
	defer s.releaseKDF()
	if lerr != nil {
		_ = VerifyArgon2id(s.dummyLogin, password)
		return lerr
	}
	if rec.Login.Empty() {
		_ = VerifyArgon2id(s.dummyLogin, password)
		return unavailable()
	}
	enc := rec.Login.Bytes()
	err := VerifyArgon2id(enc, password)
	wipeBytes(enc)
	return err
}

// VerifyCHAP checks RFC 1994 MD5(id || secret || challenge).
func (s *Service) VerifyCHAP(ctx context.Context, userID string, id byte, challenge, response []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(challenge) < s.minCHAP || len(response) != CHAPResponseLen {
		return malformed()
	}
	rec, lerr := s.lookup(userID)
	if lerr != nil {
		_ = verifyCHAP(id, s.dummyChal, challenge, response, s.minCHAP)
		return lerr
	}
	if rec.Challenge.Empty() {
		_ = verifyCHAP(id, s.dummyChal, challenge, response, s.minCHAP)
		return unavailable()
	}
	sec := rec.Challenge.Bytes()
	err := verifyCHAP(id, sec, challenge, response, s.minCHAP)
	wipeBytes(sec)
	return err
}

// VerifyMSCHAPv1 checks RFC 2433. PPP id is accepted from the wire and is not
// mixed into the DES response.
func (s *Service) VerifyMSCHAPv1(ctx context.Context, userID string, _ byte, challenge, response []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(challenge) != MSCHAPv1ChallengeLen || len(response) != MSCHAPResponseLen {
		return malformed()
	}
	rec, lerr := s.lookup(userID)
	if lerr != nil {
		_ = verifyMSCHAPv1(s.dummyChal, challenge, response)
		return lerr
	}
	if rec.Challenge.Empty() {
		_ = verifyMSCHAPv1(s.dummyChal, challenge, response)
		return unavailable()
	}
	sec := rec.Challenge.Bytes()
	err := verifyMSCHAPv1(sec, challenge, response)
	wipeBytes(sec)
	return err
}

// VerifyMSCHAPv2 checks RFC 2759 using UsernameCasePreserved output as UserName.
func (s *Service) VerifyMSCHAPv2(ctx context.Context, userID string, _ byte, challenge, response []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Shape (length, reserved, flags) is independent of user existence so a
	// malformed authenticator cannot become a username oracle via ERROR vs FAIL.
	if err := mschapv2WireOK(challenge, response); err != nil {
		return err
	}
	canon, cerr := CanonicalUsername(userID)
	rec, lerr := s.lookup(userID)
	if cerr != nil || lerr != nil {
		_ = verifyMSCHAPv2(s.dummyChal, []byte("x"), challenge, response)
		if lerr != nil {
			return lerr
		}
		return fail(KindUnknown)
	}
	if rec.Challenge.Empty() {
		_ = verifyMSCHAPv2(s.dummyChal, []byte(canon), challenge, response)
		return unavailable()
	}
	sec := rec.Challenge.Bytes()
	err := verifyMSCHAPv2(sec, []byte(canon), challenge, response)
	wipeBytes(sec)
	return err
}

// VerifyEnable checks the distinct ENABLE Argon2id verifier. Login material
// is never used as a fallback. secret is caller-owned and is not wiped.
func (s *Service) VerifyEnable(ctx context.Context, userID string, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, lerr := s.lookup(userID)
	if err := s.acquireKDF(ctx); err != nil {
		return err
	}
	defer s.releaseKDF()
	if lerr != nil {
		_ = VerifyArgon2id(s.dummyLogin, secret)
		return lerr
	}
	if rec.Enable.Empty() {
		_ = VerifyArgon2id(s.dummyLogin, secret)
		return unavailable()
	}
	enc := rec.Enable.Bytes()
	err := VerifyArgon2id(enc, secret)
	wipeBytes(enc)
	return err
}

// ChangeASCIIPassword verifies old and returns a new PHC encoding. It does
// not publish overlay state and does not derive a challenge secret. old and
// new are caller-owned and are not wiped.
func (s *Service) ChangeASCIIPassword(ctx context.Context, userID string, old, new []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(new) == 0 {
		return nil, malformed()
	}
	if err := s.VerifyASCIIOrPAP(ctx, userID, old); err != nil {
		return nil, err
	}
	v, err := s.DeriveLoginVerifier(ctx, new)
	if err != nil {
		return nil, err
	}
	return v.Bytes(), nil
}

func (s *Service) lookup(userID string) (Record, error) {
	canon, err := CanonicalUsername(userID)
	if err != nil {
		return Record{}, fail(KindUnknown)
	}
	rec, ok := s.store.Lookup(canon)
	if !ok {
		return Record{}, fail(KindUnknown)
	}
	if !rec.Enabled {
		return Record{}, fail(KindDisabled)
	}
	if rec.Restricted {
		return Record{}, fail(KindRestricted)
	}
	now := s.clock.Now()
	if rec.ValidAfter != nil && now.Before(rec.ValidAfter.UTC()) {
		return Record{}, fail(KindExpired)
	}
	if rec.ValidBefore != nil && !now.Before(rec.ValidBefore.UTC()) {
		return Record{}, fail(KindExpired)
	}
	return rec, nil
}

func (s *Service) acquireKDF(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.kdf <- struct{}{}:
		return nil
	}
}

func (s *Service) releaseKDF() {
	select {
	case <-s.kdf:
	default:
	}
}
