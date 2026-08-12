package credentials

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// Purpose identifies the intended use of a secret holder.
type Purpose string

const (
	PurposeLoginVerifier      Purpose = "login_verifier"
	PurposeChallengeSecret    Purpose = "challenge_secret"
	PurposeEnableVerifier     Purpose = "enable_verifier"
	PurposeLegacySharedSecret Purpose = "legacy_shared_secret"
	PurposeAPIBearerToken     Purpose = "api_bearer_token"
	PurposeTLSPrivateKey      Purpose = "tls_private_key"
	PurposeTLSPSK             Purpose = "tls_psk"
	PurposePassword           Purpose = "password"
	PurposeSessionCookie      Purpose = "session_cookie"
)

func (p Purpose) String() string { return string(p) }

const redactedMarker = "[redacted]"

// errNotSerializable is returned by encoding methods so secret bytes cannot
// leave the process through JSON, text, or YAML.
var errNotSerializable = errors.New("credentials: secret material is not serializable")

// secret is the unexported byte holder. Distinct exported types wrap it so a
// LoginVerifier cannot be assigned where a ChallengeSecret is required.
type secret struct {
	v []byte
}

func newSecret(b []byte) secret {
	if len(b) == 0 {
		return secret{}
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return secret{v: cp}
}

func (s secret) Redacted() string { return redactedMarker }

func (s secret) String() string { return redactedMarker }

func (s secret) GoString() string { return redactedMarker }

func (s secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redactedMarker)
}

func (s secret) MarshalJSON() ([]byte, error) {
	return nil, errNotSerializable
}

func (s secret) MarshalText() ([]byte, error) {
	return nil, errNotSerializable
}

func (s secret) MarshalYAML() (any, error) {
	return nil, errNotSerializable
}

func (s secret) LogValue() slog.Value {
	return slog.StringValue(redactedMarker)
}

func (s secret) bytes() []byte {
	if len(s.v) == 0 {
		return nil
	}
	out := make([]byte, len(s.v))
	copy(out, s.v)
	return out
}

func (s *secret) wipe() {
	if s == nil {
		return
	}
	for i := range s.v {
		s.v[i] = 0
	}
	s.v = nil
}

func (s secret) empty() bool { return len(s.v) == 0 }

func (s secret) length() int { return len(s.v) }

func (s secret) equal(other secret) bool {
	return subtle.ConstantTimeCompare(s.v, other.v) == 1
}

// Unexported purpose tags keep holder types distinct.
type (
	purposeLoginVerifier   struct{}
	purposeChallengeSecret struct{}
	purposeEnableVerifier  struct{}
	purposeSharedSecret    struct{}
	purposeTokenMaterial   struct{}
	purposeTLSPrivateKey   struct{}
	purposeTLSPSK          struct{}
	purposePassword        struct{}
	purposeSessionCookie   struct{}
)

// LoginVerifier holds a slow password-verifier encoding (ASCII/PAP).
type LoginVerifier struct {
	secret
	_ purposeLoginVerifier
}

// ChallengeSecret holds clear-equivalent CHAP/MS-CHAP material.
type ChallengeSecret struct {
	secret
	_ purposeChallengeSecret
}

// EnableVerifier holds ENABLE credential material.
type EnableVerifier struct {
	secret
	_ purposeEnableVerifier
}

// SharedSecret holds a legacy TACACS+ per-client obfuscation key.
type SharedSecret struct {
	secret
	_ purposeSharedSecret
}

// TokenMaterial holds a raw API bearer token value (returned once at create).
type TokenMaterial struct {
	secret
	_ purposeTokenMaterial
}

// TLSPrivateKey holds a TLS server identity key.
type TLSPrivateKey struct {
	secret
	_ purposeTLSPrivateKey
}

// TLSPSK holds an optional RFC 9887 external TLS PSK. It is never interchangeable
// with SharedSecret.
type TLSPSK struct {
	secret
	_ purposeTLSPSK
}

// Password holds an ephemeral clear password (ASCII/PAP or password-change).
type Password struct {
	secret
	_ purposePassword
}

// SessionCookie holds a browser session cookie value.
type SessionCookie struct {
	secret
	_ purposeSessionCookie
}

// NewLoginVerifier copies b into a login-verifier holder.
func NewLoginVerifier(b []byte) LoginVerifier {
	return LoginVerifier{secret: newSecret(b)}
}

// NewChallengeSecret copies b into a challenge-secret holder.
func NewChallengeSecret(b []byte) ChallengeSecret {
	return ChallengeSecret{secret: newSecret(b)}
}

// NewEnableVerifier copies b into an ENABLE-verifier holder.
func NewEnableVerifier(b []byte) EnableVerifier {
	return EnableVerifier{secret: newSecret(b)}
}

// NewSharedSecret copies b into a legacy shared-secret holder.
func NewSharedSecret(b []byte) SharedSecret {
	return SharedSecret{secret: newSecret(b)}
}

// NewTokenMaterial copies b into a bearer-token holder.
func NewTokenMaterial(b []byte) TokenMaterial {
	return TokenMaterial{secret: newSecret(b)}
}

// NewTLSPrivateKey copies b into a TLS private-key holder.
func NewTLSPrivateKey(b []byte) TLSPrivateKey {
	return TLSPrivateKey{secret: newSecret(b)}
}

// NewTLSPSK copies b into a TLS PSK holder.
func NewTLSPSK(b []byte) TLSPSK {
	return TLSPSK{secret: newSecret(b)}
}

// NewPassword copies b into an ephemeral password holder.
func NewPassword(b []byte) Password {
	return Password{secret: newSecret(b)}
}

// NewSessionCookie copies b into a session-cookie holder.
func NewSessionCookie(b []byte) SessionCookie {
	return SessionCookie{secret: newSecret(b)}
}

func (s LoginVerifier) Purpose() Purpose   { return PurposeLoginVerifier }
func (s ChallengeSecret) Purpose() Purpose { return PurposeChallengeSecret }
func (s EnableVerifier) Purpose() Purpose  { return PurposeEnableVerifier }
func (s SharedSecret) Purpose() Purpose    { return PurposeLegacySharedSecret }
func (s TokenMaterial) Purpose() Purpose   { return PurposeAPIBearerToken }
func (s TLSPrivateKey) Purpose() Purpose   { return PurposeTLSPrivateKey }
func (s TLSPSK) Purpose() Purpose          { return PurposeTLSPSK }
func (s Password) Purpose() Purpose        { return PurposePassword }
func (s SessionCookie) Purpose() Purpose   { return PurposeSessionCookie }

func (s LoginVerifier) Bytes() []byte   { return s.bytes() }
func (s ChallengeSecret) Bytes() []byte { return s.bytes() }
func (s EnableVerifier) Bytes() []byte  { return s.bytes() }
func (s SharedSecret) Bytes() []byte    { return s.bytes() }
func (s TokenMaterial) Bytes() []byte   { return s.bytes() }
func (s TLSPrivateKey) Bytes() []byte   { return s.bytes() }
func (s TLSPSK) Bytes() []byte          { return s.bytes() }
func (s Password) Bytes() []byte        { return s.bytes() }
func (s SessionCookie) Bytes() []byte   { return s.bytes() }

func (s LoginVerifier) Empty() bool   { return s.empty() }
func (s ChallengeSecret) Empty() bool { return s.empty() }
func (s EnableVerifier) Empty() bool  { return s.empty() }
func (s SharedSecret) Empty() bool    { return s.empty() }
func (s TokenMaterial) Empty() bool   { return s.empty() }
func (s TLSPrivateKey) Empty() bool   { return s.empty() }
func (s TLSPSK) Empty() bool          { return s.empty() }
func (s Password) Empty() bool        { return s.empty() }
func (s SessionCookie) Empty() bool   { return s.empty() }

func (s LoginVerifier) Len() int   { return s.length() }
func (s ChallengeSecret) Len() int { return s.length() }
func (s EnableVerifier) Len() int  { return s.length() }
func (s SharedSecret) Len() int    { return s.length() }
func (s TokenMaterial) Len() int   { return s.length() }
func (s TLSPrivateKey) Len() int   { return s.length() }
func (s TLSPSK) Len() int          { return s.length() }
func (s Password) Len() int        { return s.length() }
func (s SessionCookie) Len() int   { return s.length() }

func (s *LoginVerifier) Wipe() {
	if s != nil {
		s.wipe()
	}
}
func (s *ChallengeSecret) Wipe() {
	if s != nil {
		s.wipe()
	}
}
func (s *EnableVerifier) Wipe() {
	if s != nil {
		s.wipe()
	}
}
func (s *SharedSecret) Wipe() {
	if s != nil {
		s.wipe()
	}
}
func (s *TokenMaterial) Wipe() {
	if s != nil {
		s.wipe()
	}
}
func (s *TLSPrivateKey) Wipe() {
	if s != nil {
		s.wipe()
	}
}
func (s *TLSPSK) Wipe() {
	if s != nil {
		s.wipe()
	}
}
func (s *Password) Wipe() {
	if s != nil {
		s.wipe()
	}
}
func (s *SessionCookie) Wipe() {
	if s != nil {
		s.wipe()
	}
}

func (s LoginVerifier) Equal(o LoginVerifier) bool     { return s.equal(o.secret) }
func (s ChallengeSecret) Equal(o ChallengeSecret) bool { return s.equal(o.secret) }
func (s EnableVerifier) Equal(o EnableVerifier) bool   { return s.equal(o.secret) }
func (s SharedSecret) Equal(o SharedSecret) bool       { return s.equal(o.secret) }
func (s TokenMaterial) Equal(o TokenMaterial) bool     { return s.equal(o.secret) }
func (s TLSPrivateKey) Equal(o TLSPrivateKey) bool     { return s.equal(o.secret) }
func (s TLSPSK) Equal(o TLSPSK) bool                   { return s.equal(o.secret) }
func (s Password) Equal(o Password) bool               { return s.equal(o.secret) }
func (s SessionCookie) Equal(o SessionCookie) bool     { return s.equal(o.secret) }

var (
	_ fmt.Stringer   = LoginVerifier{}
	_ fmt.GoStringer = LoginVerifier{}
	_ fmt.Formatter  = LoginVerifier{}
	_ json.Marshaler = LoginVerifier{}
	_ slog.LogValuer = LoginVerifier{}
	_ fmt.Stringer   = ChallengeSecret{}
	_ fmt.Formatter  = SharedSecret{}
	_ json.Marshaler = TokenMaterial{}
	_ slog.LogValuer = TLSPrivateKey{}
	_ fmt.Stringer   = TokenDigest{}
	_ json.Marshaler = TokenDigest{}
)
