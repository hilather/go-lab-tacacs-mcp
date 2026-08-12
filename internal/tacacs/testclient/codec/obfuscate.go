package codec

import (
	"crypto/md5"
)

// Obfuscate XORs body with the RFC 8907 §4.5 MD5 pad.
// sessionID is encoded in network byte order, matching the header field.
// The key is the legacy shared secret only.
func Obfuscate(sessionID uint32, version, seqNo byte, key, body []byte) []byte {
	n := len(body)
	out := make([]byte, n)
	if n == 0 {
		return out
	}
	prefix := make([]byte, 0, 6+len(key))
	prefix = append(prefix,
		byte(sessionID>>24),
		byte(sessionID>>16),
		byte(sessionID>>8),
		byte(sessionID),
	)
	prefix = append(prefix, key...)
	prefix = append(prefix, version, seqNo)

	copy(out, body)
	var prev []byte
	off := 0
	for off < n {
		block := md5.Sum(append(prefix, prev...))
		prev = append([]byte(nil), block[:]...)
		for i := 0; i < md5.Size && off < n; i++ {
			out[off] ^= block[i]
			off++
		}
	}
	return out
}
