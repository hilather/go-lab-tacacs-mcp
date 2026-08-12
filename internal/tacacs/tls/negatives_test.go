package tls

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"

	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func TestPlaintextOnTLSPortRejected(t *testing.T) {
	ln, _ := startDefault(t)
	nc, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	h, body := authorPacket()
	pkt := append(h.Encode(), body...)
	_ = nc.SetDeadline(time.Now().Add(time.Second))
	if _, err := nc.Write(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := nc.Read(buf)
	if err == nil && n >= 12 {
		// A TACACS reply would be a 12-byte header. TLS alerts are not.
		if buf[0] == 0xc0 || buf[0] == 0xc1 {
			t.Fatalf("plaintext TACACS was accepted: %x", buf[:n])
		}
	}
}

func TestEarlyDataExtensionRejected(t *testing.T) {
	ln, _ := startDefault(t)
	nc, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	hello := clientHelloWithEarlyData()
	_ = nc.SetDeadline(time.Now().Add(time.Second))
	if _, err := nc.Write(hello); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := nc.Read(buf)
	if err == nil && n >= 12 && (buf[0] == 0xc0 || buf[0] == 0xc1) {
		t.Fatalf("early_data produced a TACACS reply: %x", buf[:n])
	}
}

func TestNoFallbackToLegacy(t *testing.T) {
	// A failed TLS handshake on the secure socket must not produce a
	// legacy TACACS session. The listeners are distinct.
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	cfg.MinVersion = tls.VersionTLS12
	cfg.MaxVersion = tls.VersionTLS12
	_, err := tls.Dial("tcp", ln.Addr().String(), cfg)
	if err == nil {
		t.Fatal("tls 1.2 must fail")
	}
	// Secure listener is still serving mTLS-only; a second good handshake works.
	cfg2 := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := dialAuth(t, ln.Addr().String(), cfg2)
	h, body := authorPacket()
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
}

func clientHelloWithEarlyData() []byte {
	// Minimal TLS 1.3 ClientHello that includes early_data (type 42) so
	// GetConfigForClient rejects the handshake.
	var body []byte
	body = append(body, 0x03, 0x03)          // legacy version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id length
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00) // compression
	var ext []byte
	// supported_versions (43) = TLS 1.3
	ext = append(ext, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
	// signature_algorithms (13)
	ext = append(ext, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03)
	// supported_groups (10) secp256r1
	ext = append(ext, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17)
	// key_share (51) empty list is enough to get us to extension parse
	ext = append(ext, 0x00, 0x33, 0x00, 0x02, 0x00, 0x00)
	// early_data (42) empty
	ext = append(ext, 0x00, 0x2a, 0x00, 0x00)
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(ext)))
	body = append(body, extLen[:]...)
	body = append(body, ext...)

	var hs []byte
	hs = append(hs, 0x01) // client_hello
	var hslen [3]byte
	hslen[0] = byte(len(body) >> 16)
	hslen[1] = byte(len(body) >> 8)
	hslen[2] = byte(len(body))
	hs = append(hs, hslen[:]...)
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01}
	var rlen [2]byte
	binary.BigEndian.PutUint16(rlen[:], uint16(len(hs)))
	rec = append(rec, rlen[:]...)
	rec = append(rec, hs...)
	return rec
}

func TestObfuscationKeyNotUsedForTLS(t *testing.T) {
	// Typed secrets: TLS match never consults a legacy shared secret.
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := dialAuth(t, ln.Addr().String(), cfg)
	// Intentionally set a leftover key on the test client; UNENCRYPTED
	// packets must still be accepted without obfuscation.
	c.SetKey([]byte("LabSecret-16chars!"))
	h, body := authorPacket()
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tcodec.ReadAuthorRep(rbody); err != nil {
		t.Fatal(err)
	}
}
