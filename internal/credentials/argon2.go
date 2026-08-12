package credentials

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params is the encode-time cost for new ASCII/PAP and ENABLE verifiers.
// Verify uses the parameters stored in the PHC string, not these values.
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// DefaultParams is the lab encode set from ADR-0002 (RFC 9106 second
// recommended memory/time, p=1 so one hash stays near 64 MiB).
var DefaultParams = Argon2Params{
	Time:    3,
	Memory:  64 * 1024,
	Threads: 1,
	SaltLen: 16,
	KeyLen:  32,
}

// TestParams is for unit tests only. It is never the encode default.
var TestParams = Argon2Params{
	Time:    1,
	Memory:  8,
	Threads: 1,
	SaltLen: 16,
	KeyLen:  32,
}

const (
	argon2Version = 19
	minSaltLen    = 8
	minKeyLen     = 16
	minMemoryKiB  = 8
	maxMemoryKiB  = 1 << 20 // 1 GiB; reject stored hashes that would DoS
	minTime       = 1
	maxTime       = 16
	minThreads    = 1
	maxThreads    = 16
)

type parsedPHC struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	hash    []byte
}

func (p Argon2Params) validEncode() error {
	if p.Time < minTime || p.Time > maxTime {
		return invalidMaterial()
	}
	if p.Memory < minMemoryKiB || p.Memory > maxMemoryKiB {
		return invalidMaterial()
	}
	if p.Threads < minThreads || p.Threads > maxThreads {
		return invalidMaterial()
	}
	if p.SaltLen < minSaltLen || p.KeyLen < minKeyLen {
		return invalidMaterial()
	}
	return nil
}

// DeriveArgon2id encodes password as a PHC argon2id string using p and entropy.
// password is caller-owned and is not wiped.
func DeriveArgon2id(password []byte, p Argon2Params, entropy io.Reader) ([]byte, error) {
	if err := p.validEncode(); err != nil {
		return nil, err
	}
	if entropy == nil {
		return nil, invalidMaterial()
	}
	salt := make([]byte, p.SaltLen)
	if _, err := io.ReadFull(entropy, salt); err != nil {
		return nil, err
	}
	sum := argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	enc := encodePHC(p, salt, sum)
	wipeBytes(sum)
	return []byte(enc), nil
}

// VerifyArgon2id reports whether password matches a PHC argon2id verifier.
// password is caller-owned and is not wiped.
func VerifyArgon2id(encoded, password []byte) error {
	parsed, err := parsePHC(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey(password, parsed.salt, parsed.time, parsed.memory, parsed.threads, uint32(len(parsed.hash)))
	ok := subtle.ConstantTimeCompare(got, parsed.hash) == 1
	wipeBytes(got)
	wipeBytes(parsed.salt)
	wipeBytes(parsed.hash)
	if !ok {
		return fail(KindWrong)
	}
	return nil
}

// ValidatePHC reports whether encoded is a usable argon2id PHC string.
func ValidatePHC(encoded []byte) error {
	parsed, err := parsePHC(encoded)
	if err != nil {
		return err
	}
	wipeBytes(parsed.salt)
	wipeBytes(parsed.hash)
	return nil
}

func encodePHC(p Argon2Params, salt, hash []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func parsePHC(encoded []byte) (parsedPHC, error) {
	s := string(encoded)
	// PHC is ASCII; reject if it is not a well-formed argon2id v=19 string.
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return parsedPHC{}, invalidMaterial()
	}
	if parts[2] != "v=19" {
		return parsedPHC{}, invalidMaterial()
	}
	mem, time, threads, err := parseCost(parts[3])
	if err != nil {
		return parsedPHC{}, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLen {
		return parsedPHC{}, invalidMaterial()
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) < minKeyLen {
		return parsedPHC{}, invalidMaterial()
	}
	return parsedPHC{memory: mem, time: time, threads: threads, salt: salt, hash: hash}, nil
}

func parseCost(s string) (mem uint32, time uint32, threads uint8, err error) {
	var sawM, sawT, sawP bool
	for _, field := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			return 0, 0, 0, invalidMaterial()
		}
		n, convErr := strconv.ParseUint(v, 10, 32)
		if convErr != nil {
			return 0, 0, 0, invalidMaterial()
		}
		switch k {
		case "m":
			if sawM || n < minMemoryKiB || n > maxMemoryKiB {
				return 0, 0, 0, invalidMaterial()
			}
			mem = uint32(n)
			sawM = true
		case "t":
			if sawT || n < minTime || n > maxTime {
				return 0, 0, 0, invalidMaterial()
			}
			time = uint32(n)
			sawT = true
		case "p":
			if sawP || n < minThreads || n > maxThreads {
				return 0, 0, 0, invalidMaterial()
			}
			threads = uint8(n)
			sawP = true
		default:
			return 0, 0, 0, invalidMaterial()
		}
	}
	if !sawM || !sawT || !sawP {
		return 0, 0, 0, invalidMaterial()
	}
	return mem, time, threads, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
