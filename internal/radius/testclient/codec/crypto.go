package codec

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"io"
)

const (
	// MaxUserPassword is RFC 2865 §5.2 (attribute Length ≤ 130).
	MaxUserPassword = 128
	papBlock        = 16
	maWireLen       = 18
)

// Wipe overwrites b. Callers must wipe unhidden passwords after use.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Equal is constant-time when lengths match.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func equal16(a, b [16]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// NewRequestAuthenticator returns a 16-byte Access-Request nonce.
// It is not a MAC and is not mixed with the shared secret.
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

func digestMD5(parts ...[]byte) [16]byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	buf := make([]byte, 0, n)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	sum := md5.Sum(buf)
	Wipe(buf)
	return sum
}

func digestHMACMD5(secret, data []byte) [16]byte {
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(data)
	var out [16]byte
	mac.Sum(out[:0])
	return out
}

// HideUserPassword hides a PAP password (RFC 2865 §5.2). The result is
// 16..128 octets, a multiple of 16. password is not retained.
func HideUserPassword(secret []byte, reqAuth [16]byte, password []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if len(password) > MaxUserPassword {
		return nil, ErrPasswordTooLong
	}
	n := len(password)
	if n == 0 {
		n = papBlock
	} else {
		n = ((n + papBlock - 1) / papBlock) * papBlock
	}
	pad := make([]byte, n)
	copy(pad, password)
	defer Wipe(pad)

	out := make([]byte, n)
	var mix []byte
	for off := 0; off < n; off += papBlock {
		var block [16]byte
		if off == 0 {
			block = digestMD5(secret, reqAuth[:])
		} else {
			block = digestMD5(secret, mix)
		}
		for i := 0; i < papBlock; i++ {
			out[off+i] = pad[off+i] ^ block[i]
		}
		mix = out[off : off+papBlock]
		Wipe(block[:])
	}
	return out, nil
}

// UnhideUserPassword reverses HideUserPassword. Trailing NUL pad is
// stripped. The caller must Wipe the returned slice after use.
func UnhideUserPassword(secret []byte, reqAuth [16]byte, hidden []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if len(hidden) < papBlock || len(hidden) > MaxUserPassword || len(hidden)%papBlock != 0 {
		return nil, ErrHiddenPassword
	}
	plain := make([]byte, len(hidden))
	for off := 0; off < len(hidden); off += papBlock {
		var block [16]byte
		if off == 0 {
			block = digestMD5(secret, reqAuth[:])
		} else {
			block = digestMD5(secret, hidden[off-papBlock:off])
		}
		for i := 0; i < papBlock; i++ {
			plain[off+i] = hidden[off+i] ^ block[i]
		}
		Wipe(block[:])
	}
	end := len(plain)
	for end > 0 && plain[end-1] == 0 {
		end--
	}
	out := make([]byte, end)
	copy(out, plain[:end])
	Wipe(plain)
	return out, nil
}

// ResponseAuthenticator is MD5(Code+ID+Length+RequestAuth+Attributes+Secret).
// Length is always computed from the attributes.
func ResponseAuthenticator(secret []byte, code Code, id uint8, reqAuth [16]byte, attrs []Attr) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	payload, err := encodeAttrs(attrs)
	if err != nil {
		return zero, err
	}
	n := HeaderLen + len(payload)
	var hdr [4]byte
	hdr[0] = byte(code)
	hdr[1] = id
	put16(hdr[2:4], uint16(n))
	return digestMD5(hdr[:], reqAuth[:], payload, secret), nil
}

// ValidateResponseAuthenticator checks packet's Authenticator against
// ResponseAuthenticator using reqAuth from the matching request.
func ValidateResponseAuthenticator(secret []byte, packet []byte, reqAuth [16]byte) error {
	declared, h, err := declaredSlice(packet)
	if err != nil {
		return err
	}
	attrs, err := decodeAttrs(declared[HeaderLen:], 0, 0)
	if err != nil {
		return err
	}
	want, err := ResponseAuthenticator(secret, h.Code, h.Identifier, reqAuth, attrs)
	if err != nil {
		return err
	}
	if !equal16(h.Authenticator, want) {
		return ErrInvalidRespAuth
	}
	return nil
}

// AccountingRequestAuthenticator is MD5(Code+ID+Length+16zero+Attributes+Secret).
// The on-wire Authenticator field is ignored.
func AccountingRequestAuthenticator(secret []byte, packetWithoutAuth []byte) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	declared, _, err := declaredSlice(packetWithoutAuth)
	if err != nil {
		return zero, err
	}
	return digestMD5(declared[:4], zero[:], declared[HeaderLen:], secret), nil
}

// ValidateAccountingRequestAuthenticator compares the packet Authenticator
// using constant-time Equal.
func ValidateAccountingRequestAuthenticator(secret []byte, packet []byte) error {
	declared, h, err := declaredSlice(packet)
	if err != nil {
		return err
	}
	want, err := AccountingRequestAuthenticator(secret, declared)
	if err != nil {
		return err
	}
	if !equal16(h.Authenticator, want) {
		return ErrInvalidAcctAuth
	}
	return nil
}

// MessageAuthenticator is HMAC-MD5 over the declared packet with every
// Message-Authenticator value replaced by 16 zero octets.
func MessageAuthenticator(secret []byte, packet []byte) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	work, err := packetWithZeroedMA(packet)
	if err != nil {
		return zero, err
	}
	return digestHMACMD5(secret, work), nil
}

// ValidateMessageAuthenticator recomputes MessageAuthenticator and compares
// the on-wire value in constant time.
func ValidateMessageAuthenticator(secret []byte, packet []byte) error {
	if len(secret) == 0 {
		return ErrEmptySecret
	}
	got, err := messageAuthenticatorValue(packet)
	if err != nil {
		return err
	}
	want, err := MessageAuthenticator(secret, packet)
	if err != nil {
		return err
	}
	if !Equal(got, want[:]) {
		return ErrInvalidMA
	}
	return nil
}

func messageAuthenticatorValue(packet []byte) ([]byte, error) {
	declared, _, err := declaredSlice(packet)
	if err != nil {
		return nil, err
	}
	attrs, err := decodeAttrs(declared[HeaderLen:], 0, 0)
	if err != nil {
		return nil, err
	}
	found := AllOf(attrs, TypeMessageAuthenticator)
	switch len(found) {
	case 0:
		return nil, ErrMissingMA
	case 1:
		if len(found[0].Value) != AuthLen {
			return nil, ErrInvalidMA
		}
		v := make([]byte, AuthLen)
		copy(v, found[0].Value)
		return v, nil
	default:
		return nil, ErrDuplicateMA
	}
}

func packetWithZeroedMA(packet []byte) ([]byte, error) {
	declared, _, err := declaredSlice(packet)
	if err != nil {
		return nil, err
	}
	attrs, err := decodeAttrs(declared[HeaderLen:], 0, 0)
	if err != nil {
		return nil, err
	}
	found := AllOf(attrs, TypeMessageAuthenticator)
	switch len(found) {
	case 0:
		return nil, ErrMissingMA
	case 1:
		if len(found[0].Value) != AuthLen {
			return nil, ErrInvalidMA
		}
	default:
		return nil, ErrDuplicateMA
	}
	work := make([]byte, len(declared))
	copy(work, declared)
	cleared := 0
	off := HeaderLen
	for off+2 <= len(work) {
		n := int(work[off+1])
		if n < 2 || off+n > len(work) {
			return nil, ErrInvalidLength
		}
		if work[off] == TypeMessageAuthenticator {
			if n != maWireLen {
				return nil, ErrInvalidMA
			}
			for i := 0; i < AuthLen; i++ {
				work[off+2+i] = 0
			}
			cleared++
		}
		off += n
	}
	if cleared != 1 {
		return nil, ErrInvalidMA
	}
	return work, nil
}

// PutMessageAuthenticator writes mac into the first type-80 value.
func PutMessageAuthenticator(packet []byte, mac [16]byte) error {
	declared, _, err := declaredSlice(packet)
	if err != nil {
		return err
	}
	off := HeaderLen
	for off+2 <= len(declared) {
		n := int(declared[off+1])
		if n < 2 || off+n > len(declared) {
			return ErrInvalidLength
		}
		if declared[off] == TypeMessageAuthenticator {
			if n != maWireLen {
				return ErrInvalidMA
			}
			copy(declared[off+2:off+2+AuthLen], mac[:])
			return nil
		}
		off += n
	}
	return ErrMissingMA
}
