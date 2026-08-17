package runtime

import (
	"io"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newULID returns a 26-character Crockford-base32 ULID.
func newULID(now time.Time, r io.Reader) (string, error) {
	var raw [16]byte
	ms := uint64(now.UTC().UnixMilli())
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	if _, err := io.ReadFull(r, raw[6:]); err != nil {
		return "", err
	}
	var out [26]byte
	// 48-bit time → 10 chars, 80-bit entropy → 16 chars.
	encodeCrockford(out[0:10], raw[0:6], 48)
	encodeCrockford(out[10:26], raw[6:16], 80)
	return string(out[:]), nil
}

func encodeCrockford(dst []byte, src []byte, bits int) {
	var acc uint64
	nbits := 0
	si := 0
	di := 0
	for di < len(dst) {
		for nbits < 5 && si < len(src) {
			acc = (acc << 8) | uint64(src[si])
			si++
			nbits += 8
		}
		if nbits < 5 {
			acc <<= uint(5 - nbits)
			nbits = 5
		}
		shift := nbits - 5
		dst[di] = crockford[(acc>>uint(shift))&31]
		acc &= (1 << uint(shift)) - 1
		nbits = shift
		di++
		_ = bits
	}
}
