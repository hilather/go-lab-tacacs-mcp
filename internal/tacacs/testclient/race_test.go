package testclient

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func TestConcurrentDialTLS(t *testing.T) {
	p := newPeerPKI(t)
	cert := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				tc := tls.Server(raw, tls13Server(cert))
				if err := tc.Handshake(); err != nil {
					_ = tc.Close()
					return
				}
				defer tc.Close()
				hdr := make([]byte, 12)
				if _, err := io.ReadFull(tc, hdr); err != nil {
					return
				}
				if n := binaryLength(hdr); n > 0 && n < 1024 {
					_, _ = io.ReadFull(tc, make([]byte, n))
				}
				_, _ = tc.Write(rawHeader(0xc0, hdr[1], hdr[2]+1, 0x01, 1, 0))
			}(c)
		}
	}()

	const n = 8
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := DialTLS(ln.Addr().String(), dnsOpts(p, "tacacs.lab.example"))
			if err != nil {
				errc <- err
				return
			}
			defer c.Close()
			h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 1}
			if err := c.WritePacket(h, []byte{0}); err != nil {
				errc <- err
				return
			}
			if _, _, err := c.ReadPacket(); err != nil {
				errc <- err
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func binaryLength(hdr []byte) uint32 {
	if len(hdr) < 12 {
		return 0
	}
	return uint32(hdr[8])<<24 | uint32(hdr[9])<<16 | uint32(hdr[10])<<8 | uint32(hdr[11])
}
