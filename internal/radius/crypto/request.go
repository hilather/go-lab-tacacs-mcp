package crypto

import (
	"crypto/rand"
	"io"
)

// NewRequestAuthenticator returns a 16-byte Access-Request nonce
// (RFC 2865 §3). It is not a MAC and is not mixed with the shared secret.
// If r is nil, crypto/rand.Reader is used.
func NewRequestAuthenticator(r io.Reader) ([16]byte, error) {
	var out [16]byte
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return [16]byte{}, err
	}
	return out, nil
}
