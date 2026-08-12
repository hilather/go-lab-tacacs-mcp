package credentials

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
)

func BenchmarkCHAPVerify(b *testing.B) {
	secret := []byte("bench-chap-secret")
	chal := bytes.Repeat([]byte{7}, 8)
	resp := CHAPResponse(0x11, secret, chal)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := verifyCHAP(0x11, secret, chal, resp, 8); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMSCHAPv1Verify(b *testing.B) {
	pw := []byte("clientPass")
	chal := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	resp := MSCHAPv1Response(pw, chal, true)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := verifyMSCHAPv1(pw, chal, resp); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMSCHAPv2Verify(b *testing.B) {
	pw := []byte("clientPass")
	user := []byte("User")
	auth := []byte{0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e, 0x3c, 0x2c, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28}
	peer := []byte{0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29, 0x5f, 0x2b, 0x3a, 0x33, 0x7c, 0x7e}
	resp := MSCHAPv2Response(pw, user, auth, peer)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := verifyMSCHAPv2(pw, user, auth, resp); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenDigest(b *testing.B) {
	tok, err := GenerateToken(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DigestToken(tok)
	}
}

func benchService(b *testing.B) *Service {
	b.Helper()
	st := NewMemory()
	s, err := NewService(st, Options{Params: TestParams, Entropy: rand.Reader, KDFWorkers: 2})
	if err != nil {
		b.Fatal(err)
	}
	return s
}

func BenchmarkTokenVerify(b *testing.B) {
	tok, err := GenerateToken(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	want := DigestToken(tok)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !EqualDigest(DigestToken(tok), want) {
			b.Fatal("mismatch")
		}
	}
}

func BenchmarkServiceCHAP(b *testing.B) {
	s := benchService(b)
	secret := []byte("bench-chap-secret")
	s.store.(*Memory).Put(Record{ID: "u", Enabled: true, Challenge: NewChallengeSecret(secret)})
	chal := bytes.Repeat([]byte{7}, 8)
	resp := CHAPResponse(0x11, secret, chal)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.VerifyCHAP(ctx, "u", 0x11, chal, resp); err != nil {
			b.Fatal(err)
		}
	}
}
