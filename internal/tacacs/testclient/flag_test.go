package testclient

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

// T98-ROLE-004: client sets UNENCRYPTED; missing flag on the reply terminates.
// Peer headers are raw 12-byte fixtures, not the server codec.
func TestTLSForcesUnencryptedAndRejectsClearFlag(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)
	cert := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})

	t.Run("client sets flag", func(t *testing.T) {
		t.Parallel()
		got := make(chan byte, 1)
		addr, _ := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
			hdr := make([]byte, 12)
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			got <- hdr[3]
			length := binary.BigEndian.Uint32(hdr[8:12])
			if length > 0 && length < 1024 {
				_, _ = io.ReadFull(c, make([]byte, length))
			}
			// Raw conforming reply: UNENCRYPTED set, length 0.
			_, _ = c.Write(rawHeader(0xc0, hdr[1], hdr[2]+1, 0x01, binary.BigEndian.Uint32(hdr[4:8]), 0))
		})
		c, err := DialTLS(addr, dnsOpts(p, "tacacs.lab.example"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 9}
		if err := c.WritePacket(h, []byte{0x00}); err != nil {
			t.Fatal(err)
		}
		select {
		case flags := <-got:
			if flags&0x01 == 0 {
				t.Fatalf("client flags %#x missing UNENCRYPTED", flags)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("peer did not observe a packet")
		}
		if _, _, err := c.ReadPacket(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing flag terminates", func(t *testing.T) {
		t.Parallel()
		addr, _ := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
			hdr := make([]byte, 12)
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			length := binary.BigEndian.Uint32(hdr[8:12])
			if length > 0 && length < 1024 {
				_, _ = io.ReadFull(c, make([]byte, length))
			}
			// Raw nonconforming reply: UNENCRYPTED clear.
			_, _ = c.Write(rawHeader(0xc0, hdr[1], hdr[2]+1, 0x00, binary.BigEndian.Uint32(hdr[4:8]), 0))
		})
		c, err := DialTLS(addr, dnsOpts(p, "tacacs.lab.example"))
		if err != nil {
			t.Fatal(err)
		}
		h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 3}
		if err := c.WritePacket(h, []byte{0x00}); err != nil {
			t.Fatal(err)
		}
		_, _, err = c.ReadPacket()
		if !errors.Is(err, ErrMissingUnencrypted) {
			t.Fatalf("err=%v, want ErrMissingUnencrypted", err)
		}
		if _, _, err := c.ReadPacket(); err == nil {
			t.Fatal("session must stay terminated")
		}
	})
}

func TestNewTLSIgnoresObfuscationKey(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	c := NewTLS(a)
	c.SetKey([]byte("LabSecret-16chars!"))
	go func() {
		h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 1}
		_ = c.WritePacket(h, []byte{0xaa})
	}()
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[3]&0x01 == 0 {
		t.Fatalf("flags %#x", hdr[3])
	}
	body := make([]byte, 1)
	if _, err := io.ReadFull(b, body); err != nil {
		t.Fatal(err)
	}
	if body[0] != 0xaa {
		t.Fatalf("body was obfuscated: %x", body)
	}
}
