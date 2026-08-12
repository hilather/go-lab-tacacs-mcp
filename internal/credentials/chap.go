package credentials

import (
	"crypto/md5"
	"crypto/subtle"
)

// DefaultMinCHAPChallenge is RFC 8907 recommended minimum (T89-FLOW-012).
const DefaultMinCHAPChallenge = 8

// CHAPResponseLen is the RFC 1994 MD5 response size.
const CHAPResponseLen = 16

// CHAPResponse is MD5(PPP_id || secret || challenge) from RFC 1994 / RFC 8907
// §5.4.2.3. The PPP identifier is part of the hash.
func CHAPResponse(id byte, secret, challenge []byte) []byte {
	h := md5.New()
	_, _ = h.Write([]byte{id})
	_, _ = h.Write(secret)
	_, _ = h.Write(challenge)
	return h.Sum(nil)
}

func verifyCHAP(id byte, secret, challenge, response []byte, minChallenge int) error {
	if minChallenge <= 0 {
		minChallenge = DefaultMinCHAPChallenge
	}
	if len(challenge) < minChallenge || len(response) != CHAPResponseLen {
		return malformed()
	}
	expected := CHAPResponse(id, secret, challenge)
	ok := subtle.ConstantTimeCompare(expected, response) == 1
	wipeBytes(expected)
	if !ok {
		return fail(KindWrong)
	}
	return nil
}
