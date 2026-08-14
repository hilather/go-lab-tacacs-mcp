package crypto

import "crypto/subtle"

// Equal reports whether a and b are the same length and contents.
// Comparison is constant-time when the lengths match.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func equal16(a, b [16]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
