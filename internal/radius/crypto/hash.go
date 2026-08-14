package crypto

import (
	"crypto/hmac"
	"crypto/md5"
)

// md5Concat is MD5 over the concatenation of parts. RADIUS/UDP is the
// only reason this helper exists (ADR 0016).
func md5Concat(parts ...[]byte) [16]byte {
	h := md5.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	var out [16]byte
	h.Sum(out[:0])
	return out
}

func hmacMD5(secret, data []byte) [16]byte {
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(data)
	var out [16]byte
	mac.Sum(out[:0])
	return out
}
