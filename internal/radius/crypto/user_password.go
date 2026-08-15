package crypto

import "crypto/md5"

const (
	// MaxUserPassword is RFC 2865 §5.2 String maximum (attribute Length ≤ 130).
	MaxUserPassword = 128
	// hiddenBlock is the User-Password XOR block size.
	hiddenBlock = 16
)

// HideUserPassword hides a PAP password (RFC 2865 §5.2). The result is
// 16..128 octets, a multiple of 16. password is not retained; the caller
// should Wipe it after this returns.
func HideUserPassword(secret []byte, reqAuth [16]byte, password []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if len(password) > MaxUserPassword {
		return nil, ErrPasswordTooLong
	}
	n := ((len(password) + hiddenBlock - 1) / hiddenBlock) * hiddenBlock
	if n == 0 {
		n = hiddenBlock
	}
	padded := make([]byte, n)
	copy(padded, password)
	defer Wipe(padded)

	hidden := make([]byte, n)
	h := md5.New()
	var digest [hiddenBlock]byte
	for i := 0; i < n; i += hiddenBlock {
		h.Reset()
		_, _ = h.Write(secret)
		if i == 0 {
			_, _ = h.Write(reqAuth[:])
		} else {
			_, _ = h.Write(hidden[i-hiddenBlock : i])
		}
		h.Sum(digest[:0])
		for j := 0; j < hiddenBlock; j++ {
			hidden[i+j] = padded[i+j] ^ digest[j]
		}
	}
	Wipe(digest[:])
	return hidden, nil
}

// UnhideUserPassword reverses HideUserPassword. Trailing NUL pad is
// stripped. The caller must Wipe the returned slice after use.
func UnhideUserPassword(secret []byte, reqAuth [16]byte, hidden []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if len(hidden) < hiddenBlock || len(hidden) > MaxUserPassword || len(hidden)%hiddenBlock != 0 {
		return nil, ErrHiddenPassword
	}
	plain := make([]byte, len(hidden))
	h := md5.New()
	var digest [hiddenBlock]byte
	for i := 0; i < len(hidden); i += hiddenBlock {
		h.Reset()
		_, _ = h.Write(secret)
		if i == 0 {
			_, _ = h.Write(reqAuth[:])
		} else {
			_, _ = h.Write(hidden[i-hiddenBlock : i])
		}
		h.Sum(digest[:0])
		for j := 0; j < hiddenBlock; j++ {
			plain[i+j] = hidden[i+j] ^ digest[j]
		}
	}
	Wipe(digest[:])
	// RFC 2865 pads with NULs; strip only the trailer so embedded NULs stay.
	end := len(plain)
	for end > 0 && plain[end-1] == 0 {
		end--
	}
	out := make([]byte, end)
	copy(out, plain[:end])
	Wipe(plain)
	return out, nil
}
