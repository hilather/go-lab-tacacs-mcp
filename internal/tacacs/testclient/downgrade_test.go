package testclient

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// T98-ROLE-002: TLS failure never falls back to legacy TACACS.
func TestDialTLSNoFallbackOnPlaintextPeer(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)
	var accepts atomic.Int32
	addr, seen := startIndependentPeer(t, nil, func(c net.Conn) {
		accepts.Add(1)
		_ = c.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		// Tempt the client: a TACACS header as if we were a legacy server.
		reply := rawHeader(0xc0, 0x02, 2, 0x01, 1, 0)
		_, _ = c.Write(reply)
		if n > 0 && (buf[0] == 0xc0 || buf[0] == 0xc1) {
			t.Errorf("plaintext peer received TACACS, not TLS: %x", buf[:n])
		}
	})
	var dials atomic.Int32
	_, err := DialTLS(addr, TLSOptions{
		ServerName: "tacacs.lab.example",
		Kind:       IdentityDNS,
		RootCAs:    p.roots,
		Timeout:    time.Second,
		Dial: func(network, address string) (net.Conn, error) {
			dials.Add(1)
			return net.DialTimeout(network, address, time.Second)
		},
	})
	if err == nil {
		t.Fatal("DialTLS must fail against a plaintext peer")
	}
	if dials.Load() != 1 {
		t.Fatalf("dials=%d, want 1 (no legacy retry)", dials.Load())
	}
	if accepts.Load() != 1 {
		t.Fatalf("accepts=%d, want 1", accepts.Load())
	}
	raw := seen.bytes()
	if len(raw) == 0 {
		t.Fatal("peer saw no bytes")
	}
	if raw[0] != 0x16 {
		t.Fatalf("first byte %#x, want TLS 0x16 (no legacy TACACS fallback)", raw[0])
	}
}

func TestDialTLSNoFallbackOnTLS12(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)
	cert := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})
	var sawTACACS atomic.Bool
	addr, seen := startIndependentPeer(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, func(c net.Conn) {
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		if n > 0 && (buf[0] == 0xc0 || buf[0] == 0xc1) {
			sawTACACS.Store(true)
		}
	})
	var dials atomic.Int32
	_, err := DialTLS(addr, TLSOptions{
		ServerName: "tacacs.lab.example",
		Kind:       IdentityDNS,
		RootCAs:    p.roots,
		Timeout:    time.Second,
		Dial: func(network, address string) (net.Conn, error) {
			dials.Add(1)
			return net.DialTimeout(network, address, time.Second)
		},
	})
	if err == nil {
		t.Fatal("TLS 1.2 must not succeed")
	}
	if dials.Load() != 1 {
		t.Fatalf("dials=%d, want 1", dials.Load())
	}
	if sawTACACS.Load() {
		t.Fatal("wrote TACACS after TLS 1.2 failure")
	}
	raw := seen.bytes()
	if len(raw) > 0 && (raw[0] == 0xc0 || raw[0] == 0xc1) {
		t.Fatalf("legacy TACACS on the wire: %x", raw[:min(16, len(raw))])
	}
}

func TestDialTLSDoesNotCallLegacyDial(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	_, err = DialTLS(ln.Addr().String(), dnsOpts(p, "tacacs.lab.example"))
	if err == nil {
		t.Fatal("expected handshake failure")
	}
	// Legacy Dial would succeed (TCP is up) and write an obfuscated packet.
	// Proving DialTLS failed is the no-fallback contract; a second probe
	// with Dial is a different API and must stay opt-in.
}

func rawHeader(ver, typ, seq, flags byte, session, length uint32) []byte {
	b := make([]byte, 12)
	b[0] = ver
	b[1] = typ
	b[2] = seq
	b[3] = flags
	binary.BigEndian.PutUint32(b[4:8], session)
	binary.BigEndian.PutUint32(b[8:12], length)
	return b
}
