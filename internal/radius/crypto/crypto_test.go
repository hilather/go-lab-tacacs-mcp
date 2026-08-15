package crypto

import (
	"bytes"
	"crypto/md5"
	"errors"
	"io"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

func testSecret(t *testing.T) []byte {
	t.Helper()
	return []byte("lab-radius-test-secret-32octets!!")
}

func testRA(t *testing.T) [16]byte {
	t.Helper()
	return [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
}

func TestNewRequestAuthenticatorIsNonce(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	fixed := bytes.Repeat([]byte{0x5a}, 16)
	got, err := NewRequestAuthenticator(bytes.NewReader(fixed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], fixed) {
		t.Fatal("nonce is not the raw random bytes")
	}
	// Must not mix the shared secret into the Access-Request Authenticator.
	mixed := md5.Sum(append(secret, fixed...))
	if bytes.Equal(got[:], mixed[:]) {
		t.Fatal("Access-Request Authenticator must not be a MAC")
	}
	a, err := NewRequestAuthenticator(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRequestAuthenticator(nil)
	if err != nil {
		t.Fatal(err)
	}
	if equal16(a, b) {
		t.Fatal("two nonces collided")
	}
}

func TestNewRequestAuthenticatorShortRead(t *testing.T) {
	t.Parallel()
	_, err := NewRequestAuthenticator(bytes.NewReader([]byte{1, 2, 3}))
	if !errors.Is(err, io.ErrUnexpectedEOF) && err == nil {
		t.Fatalf("err=%v", err)
	}
}

func TestEmptySecretRejected(t *testing.T) {
	t.Parallel()
	ra := testRA(t)
	if _, err := HideUserPassword(nil, ra, []byte("x")); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("hide: %v", err)
	}
	if _, err := UnhideUserPassword(nil, ra, bytes.Repeat([]byte{1}, 16)); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("unhide: %v", err)
	}
	if _, err := ResponseAuthenticator(nil, codec.CodeAccessAccept, 1, 0, ra, nil); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("response: %v", err)
	}
	pkt := make([]byte, 20)
	pkt[0] = byte(codec.CodeAccountingRequest)
	pkt[3] = 20
	if _, err := AccountingRequestAuthenticator(nil, pkt); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("acct: %v", err)
	}
	if _, err := MessageAuthenticator(nil, pkt); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("ma: %v", err)
	}
}

func TestHideRejectsTooLong(t *testing.T) {
	t.Parallel()
	_, err := HideUserPassword(testSecret(t), testRA(t), bytes.Repeat([]byte{'a'}, MaxUserPassword+1))
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("err=%v", err)
	}
}

func TestUnhideRejectsBadLength(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	ra := testRA(t)
	for _, n := range []int{0, 15, 17, 129} {
		_, err := UnhideUserPassword(secret, ra, bytes.Repeat([]byte{1}, n))
		if !errors.Is(err, ErrHiddenPassword) {
			t.Fatalf("n=%d err=%v", n, err)
		}
	}
}

func TestHideUnhideRoundTrip(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	ra := testRA(t)
	for _, pw := range [][]byte{
		nil,
		{},
		[]byte("a"),
		[]byte("exactly-16-bytes"),
		append(bytes.Repeat([]byte{'x'}, 15), 0x00),
		bytes.Repeat([]byte{'z'}, 128),
	} {
		hidden, err := HideUserPassword(secret, ra, pw)
		if err != nil {
			t.Fatalf("hide %q: %v", pw, err)
		}
		if len(hidden)%16 != 0 || len(hidden) < 16 || len(hidden) > 128 {
			t.Fatalf("hidden len %d", len(hidden))
		}
		got, err := UnhideUserPassword(secret, ra, hidden)
		if err != nil {
			t.Fatalf("unhide: %v", err)
		}
		want := pw
		if want == nil {
			want = []byte{}
		}
		// trailing NULs in the password cannot be distinguished from pad
		for len(want) > 0 && want[len(want)-1] == 0 {
			want = want[:len(want)-1]
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round-trip mismatch len=%d", len(pw))
		}
		Wipe(got)
	}
}

func TestUnhideWrongSecretDoesNotMatch(t *testing.T) {
	t.Parallel()
	ra := testRA(t)
	hidden, err := HideUserPassword(testSecret(t), ra, []byte("correct-horse"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnhideUserPassword([]byte("other-secret-not-the-same-value"), ra, hidden)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, []byte("correct-horse")) {
		t.Fatal("wrong secret produced the password")
	}
	Wipe(got)
}

func TestResponseAuthenticatorLengthMismatch(t *testing.T) {
	t.Parallel()
	_, err := ResponseAuthenticator(testSecret(t), codec.CodeAccessAccept, 1, 21, testRA(t), nil)
	if !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("err=%v", err)
	}
}

func TestResponseAuthenticatorZeroLengthComputes(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	ra := testRA(t)
	got, err := ResponseAuthenticator(secret, codec.CodeAccessReject, 3, 0, ra, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ResponseAuthenticator(secret, codec.CodeAccessReject, 3, 20, ra, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !equal16(got, want) {
		t.Fatal("zero length should compute 20")
	}
}

func TestValidateResponseAuthenticatorTamper(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	ra := testRA(t)
	auth, err := ResponseAuthenticator(secret, codec.CodeAccessAccept, 1, 20, ra, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt := make([]byte, 20)
	pkt[0] = byte(codec.CodeAccessAccept)
	pkt[1] = 1
	pkt[3] = 20
	copy(pkt[4:20], auth[:])
	if err := ValidateResponseAuthenticator(secret, pkt, ra); err != nil {
		t.Fatal(err)
	}
	pkt[4] ^= 0x01
	if err := ValidateResponseAuthenticator(secret, pkt, ra); !errors.Is(err, ErrInvalidResponseAuthenticator) {
		t.Fatalf("err=%v", err)
	}
}

func TestAccountingAuthenticatorIgnoresOnWireField(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	pkt := make([]byte, 20)
	pkt[0] = byte(codec.CodeAccountingRequest)
	pkt[1] = 4
	pkt[3] = 20
	copy(pkt[4:20], bytes.Repeat([]byte{0xff}, 16))
	got, err := AccountingRequestAuthenticator(secret, pkt)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 20)
	copy(zeros, pkt[:4])
	want, err := AccountingRequestAuthenticator(secret, zeros)
	if err != nil {
		t.Fatal(err)
	}
	if !equal16(got, want) {
		t.Fatal("on-wire authenticator must be treated as zeros")
	}
	if err := ValidateAccountingRequestAuthenticator(secret, pkt); !errors.Is(err, ErrInvalidAccountingAuthenticator) {
		t.Fatalf("ff field should fail validate: %v", err)
	}
	copy(pkt[4:20], got[:])
	if err := ValidateAccountingRequestAuthenticator(secret, pkt); err != nil {
		t.Fatal(err)
	}
}

func TestAccountingAuthenticatorZerosPresentMA(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	attrs := attribute.RawSet{
		{Type: attribute.TypeAcctStatusType, Value: []byte{0, 0, 0, 1}},
		{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
	}
	pkt := codec.Packet{Code: codec.CodeAccountingRequest, Identifier: 9, Attributes: attrs}
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := AccountingRequestAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Authenticator = auth
	raw, err = codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := MessageAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Attributes[1].Value = append([]byte(nil), mac[:]...)
	signed, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAccountingRequestAuthenticator(secret, signed); err != nil {
		t.Fatalf("authenticator must ignore MA value: %v", err)
	}
	if err := ValidateMessageAuthenticator(secret, signed); err != nil {
		t.Fatalf("ma: %v", err)
	}
}

func TestAccountingAuthenticatorShortPacket(t *testing.T) {
	t.Parallel()
	_, err := AccountingRequestAuthenticator(testSecret(t), make([]byte, 19))
	if !errors.Is(err, ErrPacketShort) {
		t.Fatalf("err=%v", err)
	}
}

func TestMessageAuthenticatorMissingDuplicateWrongLength(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	ra := testRA(t)
	base := codec.Packet{Code: codec.CodeAccessRequest, Identifier: 1, Authenticator: ra}
	raw, err := codec.Encode(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MessageAuthenticator(secret, raw); !errors.Is(err, ErrMissingMessageAuthenticator) {
		t.Fatalf("missing: %v", err)
	}
	if err := ValidateMessageAuthenticator(secret, raw); !errors.Is(err, ErrMissingMessageAuthenticator) {
		t.Fatalf("validate missing: %v", err)
	}

	dup := base
	dup.Attributes = attribute.RawSet{
		{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
		{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
	}
	raw, err = codec.Encode(dup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MessageAuthenticator(secret, raw); !errors.Is(err, ErrDuplicateMessageAuthenticator) {
		t.Fatalf("dup: %v", err)
	}

	bad := base
	bad.Attributes = attribute.RawSet{
		{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 15)},
	}
	raw, err = codec.Encode(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MessageAuthenticator(secret, raw); !errors.Is(err, ErrInvalidMessageAuthenticator) {
		t.Fatalf("len: %v", err)
	}
}

func TestMessageAuthenticatorZerosValueDuringCompute(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	ra := testRA(t)
	zeroMA := codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    2,
		Authenticator: ra,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab")},
			{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
		},
	}
	filledMA := zeroMA
	filledMA.Attributes = zeroMA.Attributes.Clone()
	copy(filledMA.Attributes[1].Value, bytes.Repeat([]byte{0xaa}, 16))
	zraw, err := codec.Encode(zeroMA)
	if err != nil {
		t.Fatal(err)
	}
	fraw, err := codec.Encode(filledMA)
	if err != nil {
		t.Fatal(err)
	}
	a, err := MessageAuthenticator(secret, zraw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MessageAuthenticator(secret, fraw)
	if err != nil {
		t.Fatal(err)
	}
	if !equal16(a, b) {
		t.Fatal("compute must zero the MA value")
	}
}

func TestValidateMessageAuthenticatorTamper(t *testing.T) {
	t.Parallel()
	secret := testSecret(t)
	ra := testRA(t)
	p := codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    3,
		Authenticator: ra,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
		},
	}
	raw, err := codec.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := MessageAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	copy(raw[22:38], mac[:])
	if err := ValidateMessageAuthenticator(secret, raw); err != nil {
		t.Fatal(err)
	}
	raw[22] ^= 0x01
	if err := ValidateMessageAuthenticator(secret, raw); !errors.Is(err, ErrInvalidMessageAuthenticator) {
		t.Fatalf("tamper ma: %v", err)
	}
	copy(raw[22:38], mac[:])
	raw[4] ^= 0x01
	if err := ValidateMessageAuthenticator(secret, raw); !errors.Is(err, ErrInvalidMessageAuthenticator) {
		t.Fatalf("tamper ra: %v", err)
	}
}

func TestEqualConstantTimeLengths(t *testing.T) {
	t.Parallel()
	a := []byte{1, 2, 3, 4}
	if !Equal(a, []byte{1, 2, 3, 4}) {
		t.Fatal("equal")
	}
	if Equal(a, []byte{1, 2, 3, 5}) {
		t.Fatal("mismatch")
	}
	if Equal(a, []byte{1, 2, 3}) {
		t.Fatal("length")
	}
	if Equal(nil, []byte{1}) {
		t.Fatal("nil")
	}
	if !Equal(nil, nil) {
		t.Fatal("both nil")
	}
}

func TestWipe(t *testing.T) {
	t.Parallel()
	b := []byte("secret")
	Wipe(b)
	if !bytes.Equal(b, make([]byte, 6)) {
		t.Fatalf("wipe leftover %q", b)
	}
	Wipe(nil)
}
