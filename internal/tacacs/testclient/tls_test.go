package testclient

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

// T98-ROLE-001: first bytes are TLS handshake, never a TACACS header.
func TestDialTLSBeginsImmediately(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)
	cert := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})
	addr, seen := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
		_, _ = c.Read(make([]byte, 32))
	})
	c, err := DialTLS(addr, dnsOpts(p, "tacacs.lab.example"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.OverTLS() {
		t.Fatal("conn is not in TLS client-role mode")
	}
	raw := seen.bytes()
	if len(raw) == 0 {
		t.Fatal("peer saw no client bytes")
	}
	if raw[0] != 0x16 {
		t.Fatalf("first byte %#x, want TLS handshake 0x16 (not TACACS 0xc0/0xc1)", raw[0])
	}
	if raw[0] == 0xc0 || raw[0] == 0xc1 {
		t.Fatal("TACACS bytes written before TLS handshake")
	}
}

// T98-ROLE-005: ClientHello must not include early_data (extension 42).
func TestDialTLSClientHelloHasNoEarlyData(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)
	cert := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})
	addr, seen := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
		_, _ = c.Read(make([]byte, 32))
	})
	c, err := DialTLS(addr, dnsOpts(p, "tacacs.lab.example"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	hello, err := clientHelloFromRecord(seen.bytes())
	if err != nil {
		t.Fatal(err)
	}
	exts := helloExtensions(t, hello)
	if _, ok := exts[42]; ok {
		t.Fatal("ClientHello included early_data (type 42)")
	}
	if _, ok := exts[0]; !ok {
		t.Fatal("expected server_name extension for configured SNI")
	}
}

func TestDialTLSNoPacketBeforeHandshakeReturns(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)
	cert := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})
	started := make(chan struct{})
	addr, seen := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
		close(started)
		_, _ = c.Read(make([]byte, 64))
	})
	c, err := DialTLS(addr, dnsOpts(p, "tacacs.lab.example"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	<-started
	// Handshake completed before Conn was returned; any TACACS write is after.
	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 7}
	if err := c.WritePacket(h, []byte{0}); err != nil {
		t.Fatal(err)
	}
	raw := seen.bytes()
	if len(raw) == 0 || raw[0] != 0x16 {
		t.Fatalf("wire prefix %#x", raw)
	}
}

func clientHelloFromRecord(b []byte) ([]byte, error) {
	if len(b) < 5 {
		return nil, errShort("tls record")
	}
	if b[0] != 0x16 {
		return nil, errShort("not handshake record")
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+n {
		return nil, errShort("handshake truncated")
	}
	hs := b[5 : 5+n]
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, errShort("not clienthello")
	}
	return hs[4:], nil
}

type shortErr string

func (e shortErr) Error() string { return string(e) }

func errShort(s string) error { return shortErr(s) }

func helloExtensions(t *testing.T, body []byte) map[uint16][]byte {
	t.Helper()
	// legacy_version(2) + random(32) + session_id + ciphers + compression + extensions
	if len(body) < 35 {
		t.Fatalf("hello body %d", len(body))
	}
	off := 34
	sidLen := int(body[off])
	off++
	off += sidLen
	if off+2 > len(body) {
		t.Fatal("no cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + csLen
	if off >= len(body) {
		t.Fatal("no compression")
	}
	compLen := int(body[off])
	off++
	off += compLen
	if off+2 > len(body) {
		t.Fatal("no extensions")
	}
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	end := off + extLen
	if end > len(body) {
		end = len(body)
	}
	out := map[uint16][]byte{}
	for off+4 <= end {
		typ := binary.BigEndian.Uint16(body[off : off+2])
		n := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+n > end {
			break
		}
		out[typ] = append([]byte(nil), body[off:off+n]...)
		off += n
	}
	return out
}
