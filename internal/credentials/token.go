package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
)

// TokenByteLength is the generated API bearer size (≥256 bits).
const TokenByteLength = 32

// TokenDigestLength is SHA-256 output size.
const TokenDigestLength = sha256.Size

type purposeTokenDigest struct{}

// TokenDigest is SHA-256(token). It is not the bearer value but is still
// redacted so hash-index material cannot leak through fmt/JSON.
type TokenDigest struct {
	secret
	_ purposeTokenDigest
}

// NewTokenDigest copies b. Callers should pass a SHA-256 digest.
func NewTokenDigest(b []byte) TokenDigest {
	return TokenDigest{secret: newSecret(b)}
}

func (d TokenDigest) Purpose() Purpose { return PurposeAPIBearerToken }

func (d TokenDigest) Bytes() []byte { return d.bytes() }

func (d TokenDigest) Empty() bool { return d.empty() }

func (d TokenDigest) Len() int { return d.length() }

func (d *TokenDigest) Wipe() {
	if d != nil {
		d.wipe()
	}
}

func (d TokenDigest) Equal(o TokenDigest) bool { return d.equal(o.secret) }

// GenerateToken returns TokenByteLength cryptographically random bytes.
func GenerateToken(entropy io.Reader) (TokenMaterial, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	b := make([]byte, TokenByteLength)
	if _, err := io.ReadFull(entropy, b); err != nil {
		return TokenMaterial{}, err
	}
	return NewTokenMaterial(b), nil
}

// DigestToken returns SHA-256 of the raw token bytes.
func DigestToken(m TokenMaterial) TokenDigest {
	sum := sha256.Sum256(m.Bytes())
	return NewTokenDigest(sum[:])
}

// EqualDigest compares two SHA-256 token digests in constant time.
func EqualDigest(a, b TokenDigest) bool {
	ab, bb := a.Bytes(), b.Bytes()
	if len(ab) != TokenDigestLength || len(bb) != TokenDigestLength {
		eq := subtle.ConstantTimeCompare(ab, bb) == 1
		wipeBytes(ab)
		wipeBytes(bb)
		return eq && len(ab) == len(bb) && len(ab) == TokenDigestLength
	}
	ok := subtle.ConstantTimeCompare(ab, bb) == 1
	wipeBytes(ab)
	wipeBytes(bb)
	return ok
}

// DigestIndex is a map key for hash-indexed token lookup.
func DigestIndex(d TokenDigest) [TokenDigestLength]byte {
	var out [TokenDigestLength]byte
	b := d.Bytes()
	copy(out[:], b)
	wipeBytes(b)
	return out
}
