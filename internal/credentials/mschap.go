package credentials

import (
	"crypto/des"
	"crypto/sha1"
	"crypto/subtle"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const (
	// MSCHAPv1ChallengeLen is the RFC 8907 / RFC 2433 authenticator challenge.
	MSCHAPv1ChallengeLen = 8
	// MSCHAPv2ChallengeLen is the RFC 8907 / RFC 2759 authenticator challenge.
	MSCHAPv2ChallengeLen = 16
	// MSCHAPResponseLen is the 49-octet MS-CHAP response (v1 and v2).
	MSCHAPResponseLen = 49
	mschapLMLen       = 24
	mschapNTLen       = 24
	mschapPeerLen     = 16
	mschapReservedLen = 8
)

// lmMagic is the RFC 2433 DesHash constant "KGS!@#$%".
var lmMagic = []byte("KGS!@#$%")

// NtPasswordHash is MD4(UTF-16LE(password)) from RFC 2433 / RFC 2759.
func NtPasswordHash(password []byte) []byte {
	u := utf16LE(password)
	h := md4.New()
	_, _ = h.Write(u)
	wipeBytes(u)
	return h.Sum(nil)
}

// LmPasswordHash is the RFC 2433 LAN Manager hash of an OEM/ASCII password.
func LmPasswordHash(password []byte) []byte {
	var padded [14]byte
	upper := toOEMUpper(password)
	copy(padded[:], upper)
	wipeBytes(upper)
	out := make([]byte, 16)
	copy(out[0:8], desEncryptBlock(padded[0:7], lmMagic))
	copy(out[8:16], desEncryptBlock(padded[7:14], lmMagic))
	return out
}

// ChallengeResponse is the RFC 2433 24-octet DES triple over an 8-byte challenge.
func ChallengeResponse(challenge, passwordHash []byte) []byte {
	var z [21]byte
	copy(z[:], passwordHash)
	out := make([]byte, mschapNTLen)
	copy(out[0:8], desEncryptBlock(z[0:7], challenge))
	copy(out[8:16], desEncryptBlock(z[7:14], challenge))
	copy(out[16:24], desEncryptBlock(z[14:21], challenge))
	return out
}

// MSCHAPv1Response builds the 49-octet RFC 2433 response (LM || NT || flags).
// flags=1 selects the NT-response. PPP id is not an input to this calculation.
func MSCHAPv1Response(password, challenge []byte, useNT bool) []byte {
	out := make([]byte, MSCHAPResponseLen)
	lm := ChallengeResponse(challenge, LmPasswordHash(password))
	nt := ChallengeResponse(challenge, NtPasswordHash(password))
	copy(out[0:24], lm)
	copy(out[24:48], nt)
	if useNT {
		out[48] = 1
	}
	wipeBytes(lm)
	wipeBytes(nt)
	return out
}

// MSCHAPv2ChallengeHash is SHA1(peer || authenticator || username)[:8].
// username must already be UsernameCasePreserved lookup output (ADR-0002).
func MSCHAPv2ChallengeHash(peerChallenge, authChallenge, username []byte) []byte {
	h := sha1.New()
	_, _ = h.Write(peerChallenge)
	_, _ = h.Write(authChallenge)
	_, _ = h.Write(username)
	sum := h.Sum(nil)
	out := make([]byte, 8)
	copy(out, sum[:8])
	return out
}

// MSCHAPv2NTResponse is the 24-octet NT-response from RFC 2759.
func MSCHAPv2NTResponse(password, username, authChallenge, peerChallenge []byte) []byte {
	ch := MSCHAPv2ChallengeHash(peerChallenge, authChallenge, username)
	nt := ChallengeResponse(ch, NtPasswordHash(password))
	wipeBytes(ch)
	return nt
}

// MSCHAPv2Response builds the 49-octet RFC 2759 response.
func MSCHAPv2Response(password, username, authChallenge, peerChallenge []byte) []byte {
	out := make([]byte, MSCHAPResponseLen)
	copy(out[0:16], peerChallenge)
	// reserved [16:24] stays zero
	nt := MSCHAPv2NTResponse(password, username, authChallenge, peerChallenge)
	copy(out[24:48], nt)
	wipeBytes(nt)
	return out
}

func verifyMSCHAPv1(password, challenge, response []byte) error {
	if len(challenge) != MSCHAPv1ChallengeLen || len(response) != MSCHAPResponseLen {
		return malformed()
	}
	useNT := response[48] != 0
	var expected []byte
	if useNT {
		expected = ChallengeResponse(challenge, NtPasswordHash(password))
		ok := subtle.ConstantTimeCompare(expected, response[24:48]) == 1
		wipeBytes(expected)
		if !ok {
			return fail(KindWrong)
		}
		return nil
	}
	expected = ChallengeResponse(challenge, LmPasswordHash(password))
	ok := subtle.ConstantTimeCompare(expected, response[0:24]) == 1
	wipeBytes(expected)
	if !ok {
		return fail(KindWrong)
	}
	return nil
}

func verifyMSCHAPv2(password, username, authChallenge, response []byte) error {
	if len(authChallenge) != MSCHAPv2ChallengeLen || len(response) != MSCHAPResponseLen {
		return malformed()
	}
	// RFC 2759 reserved octets must be zero.
	var reserved [mschapReservedLen]byte
	if subtle.ConstantTimeCompare(response[16:24], reserved[:]) != 1 {
		return malformed()
	}
	peer := response[0:mschapPeerLen]
	expected := MSCHAPv2NTResponse(password, username, authChallenge, peer)
	ok := subtle.ConstantTimeCompare(expected, response[24:48]) == 1
	wipeBytes(expected)
	if !ok {
		return fail(KindWrong)
	}
	return nil
}

func utf16LE(password []byte) []byte {
	u := utf16.Encode([]rune(string(password)))
	out := make([]byte, len(u)*2)
	for i, c := range u {
		out[i*2] = byte(c)
		out[i*2+1] = byte(c >> 8)
	}
	return out
}

func toOEMUpper(password []byte) []byte {
	// Lab challenge secrets are ASCII; map to 7-bit OEM uppercase and
	// truncate to the 14-octet LM limit.
	out := make([]byte, 0, 14)
	for _, b := range password {
		if len(out) == 14 {
			break
		}
		c := b
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out = append(out, c)
	}
	return out
}

func desEncryptBlock(key7, data8 []byte) []byte {
	var key8 [8]byte
	key8[0] = key7[0]
	key8[1] = (key7[0] << 7) | (key7[1] >> 1)
	key8[2] = (key7[1] << 6) | (key7[2] >> 2)
	key8[3] = (key7[2] << 5) | (key7[3] >> 3)
	key8[4] = (key7[3] << 4) | (key7[4] >> 4)
	key8[5] = (key7[4] << 3) | (key7[5] >> 5)
	key8[6] = (key7[5] << 2) | (key7[6] >> 6)
	key8[7] = key7[6] << 1
	block, err := des.NewCipher(key8[:])
	if err != nil {
		return make([]byte, 8)
	}
	out := make([]byte, 8)
	block.Encrypt(out, data8)
	return out
}
