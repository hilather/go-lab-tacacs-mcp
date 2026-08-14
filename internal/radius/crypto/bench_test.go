package crypto

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

var (
	benchAuth [16]byte
	benchErr  error
	benchHide []byte
)

func benchSecret() []byte {
	return []byte("lab-radius-test-secret-32octets!!")
}

func BenchmarkResponseAuthenticator(b *testing.B) {
	secret := benchSecret()
	ra := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	attrs := attribute.RawSet{{Type: 18, Value: []byte("ok")}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := ResponseAuthenticator(secret, codec.CodeAccessAccept, 1, 0, ra, attrs)
		if err != nil {
			b.Fatal(err)
		}
		benchAuth = got
	}
}

func BenchmarkAccountingRequestAuthenticator(b *testing.B) {
	secret := benchSecret()
	pkt := make([]byte, 26)
	pkt[0] = byte(codec.CodeAccountingRequest)
	pkt[1] = 1
	pkt[3] = 26
	pkt[20] = 40
	pkt[21] = 6
	pkt[25] = 1
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := AccountingRequestAuthenticator(secret, pkt)
		if err != nil {
			b.Fatal(err)
		}
		benchAuth = got
	}
}

func BenchmarkHideUserPassword(b *testing.B) {
	secret := benchSecret()
	ra := [16]byte{1}
	pw := []byte("lab-user-password")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := HideUserPassword(secret, ra, pw)
		if err != nil {
			b.Fatal(err)
		}
		benchHide = got
	}
}

func BenchmarkUnhideUserPassword(b *testing.B) {
	secret := benchSecret()
	ra := [16]byte{1}
	hidden, err := HideUserPassword(secret, ra, []byte("lab-user-password"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := UnhideUserPassword(secret, ra, hidden)
		if err != nil {
			b.Fatal(err)
		}
		Wipe(got)
		benchHide = got
	}
}

func BenchmarkMessageAuthenticator(b *testing.B) {
	secret := benchSecret()
	p := codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    1,
		Authenticator: [16]byte{9},
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab")},
			{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
		},
	}
	raw, err := codec.Encode(p)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := MessageAuthenticator(secret, raw)
		if err != nil {
			b.Fatal(err)
		}
		benchAuth = got
	}
}

func BenchmarkValidateMessageAuthenticator(b *testing.B) {
	secret := benchSecret()
	p := codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    1,
		Authenticator: [16]byte{9},
		Attributes: attribute.RawSet{
			{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
		},
	}
	raw, err := codec.Encode(p)
	if err != nil {
		b.Fatal(err)
	}
	mac, err := MessageAuthenticator(secret, raw)
	if err != nil {
		b.Fatal(err)
	}
	copy(raw[22:38], mac[:])
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchErr = ValidateMessageAuthenticator(secret, raw)
		if benchErr != nil {
			b.Fatal(benchErr)
		}
	}
}
