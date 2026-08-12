package credentials

import (
	"context"
	"crypto/rand"
	"testing"
)

// KDF benches live here, not under internal/{tacacs,policy,state}, so
// `make bench` keeps its ordinary hot-path set.

func BenchmarkArgon2idVerify(b *testing.B) {
	pw := []byte("bench-password")
	enc, err := DeriveArgon2id(pw, DefaultParams, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := VerifyArgon2id(enc, pw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArgon2idVerifyParallel(b *testing.B) {
	st := NewMemory()
	s, err := NewService(st, Options{
		Params:     DefaultParams,
		Entropy:    rand.Reader,
		KDFWorkers: 2,
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	v, err := s.DeriveLoginVerifier(ctx, []byte("bench-password"))
	if err != nil {
		b.Fatal(err)
	}
	st.Put(Record{ID: "bench", Enabled: true, Login: v})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := s.VerifyASCIIOrPAP(ctx, "bench", []byte("bench-password")); err != nil {
				b.Error(err)
			}
		}
	})
}
