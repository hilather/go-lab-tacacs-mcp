package peap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Server is a server-authenticated TLS 1.3 endpoint for a PEAP tunnel.
// Inner EAP is not interpreted.
type Server struct {
	cfg *tls.Config
}

// NewServer requires a server certificate and pins TLS 1.3 (ADR 0004).
func NewServer(cert tls.Certificate) (*Server, error) {
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, errors.New("peap: server certificate required")
	}
	return &Server{cfg: &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		SessionTicketsDisabled: true,
	}}, nil
}

// TLSConfig returns a clone of the PEAP TLS 1.3 server config.
func (s *Server) TLSConfig() *tls.Config {
	if s == nil || s.cfg == nil {
		return nil
	}
	return s.cfg.Clone()
}

// HandshakeWithClient completes a server-authenticated TLS 1.3 handshake
// against crypto/tls as the peer and returns the server TLS records that a
// PEAP tunnel would send after PEAP Start. Inner EAP is not carried.
func (s *Server) HandshakeWithClient() ([]byte, error) {
	if s == nil || s.cfg == nil || len(s.cfg.Certificates) == 0 || len(s.cfg.Certificates[0].Certificate) == 0 {
		return nil, errors.New("peap: nil server")
	}
	leaf, err := x509.ParseCertificate(s.cfg.Certificates[0].Certificate[0])
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	a, b := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)
	tap := &recordTap{Conn: a}
	type srvOut struct {
		records []byte
		version uint16
		err     error
	}
	srvC := make(chan srvOut, 1)
	cliC := make(chan error, 1)
	go func() {
		conn := tls.Server(tap, s.cfg.Clone())
		err := conn.Handshake()
		out := srvOut{err: err}
		if err == nil {
			out.records = tap.Bytes()
			out.version = conn.ConnectionState().Version
		}
		_ = conn.Close()
		srvC <- out
	}()
	go func() {
		conn := tls.Client(b, &tls.Config{
			MinVersion:             tls.VersionTLS13,
			MaxVersion:             tls.VersionTLS13,
			ServerName:             "peap.lab.example",
			RootCAs:                roots,
			SessionTicketsDisabled: true,
		})
		err := conn.Handshake()
		_ = conn.Close()
		cliC <- err
	}()
	srv := <-srvC
	if err := <-cliC; err != nil && srv.err == nil {
		srv.err = err
	}
	if srv.err != nil {
		return nil, srv.err
	}
	if srv.version != tls.VersionTLS13 {
		return nil, fmt.Errorf("peap: negotiated %#x, want TLS 1.3", srv.version)
	}
	if len(srv.records) == 0 {
		return nil, errors.New("peap: empty TLS-in-EAP server records")
	}
	return srv.records, nil
}

type recordTap struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (t *recordTap) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.buf = append(t.buf, p...)
	t.mu.Unlock()
	return t.Conn.Write(p)
}

func (t *recordTap) Bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.buf...)
}
