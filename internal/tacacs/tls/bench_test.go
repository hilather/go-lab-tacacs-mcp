package tls

import (
	"crypto/tls"
	"testing"
)

func BenchmarkFullHandshake(b *testing.B) {
	ln, pki := startDefault(b)
	cfg := clientTLS(b, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if err := c.Handshake(); err != nil {
			b.Fatal(err)
		}
		_ = c.Close()
	}
}

func BenchmarkResumedHandshake(b *testing.B) {
	ln, pki := startDefault(b)
	cache := tls.NewLRUClientSessionCache(32)
	cfg := clientTLS(b, pki, pki.ClientOKCert, pki.ClientOKKey, "", cache)
	c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
	if err != nil {
		b.Fatal(err)
	}
	if err := c.Handshake(); err != nil {
		b.Fatal(err)
	}
	_ = c.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if err := c.Handshake(); err != nil {
			b.Fatal(err)
		}
		if !c.ConnectionState().DidResume {
			b.Fatal("expected resume")
		}
		_ = c.Close()
	}
}

func BenchmarkPostHandshakeAuthor(b *testing.B) {
	ln, pki := startDefault(b)
	cfg := clientTLS(b, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := dialAuth(b, ln.Addr().String(), cfg)
	h, body := authorPacket()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.SessionID = uint32(i + 1)
		if err := c.WritePacket(h, body); err != nil {
			b.Fatal(err)
		}
		if _, _, err := c.ReadPacket(); err != nil {
			b.Fatal(err)
		}
	}
}
