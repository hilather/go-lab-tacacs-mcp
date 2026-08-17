package peap

import (
	"crypto/tls"
	"errors"
	"sync"
	"time"
)

// Tunnel is one server-authenticated TLS 1.3 PEAP session. Client TLS
// records are pushed in; server records are pulled out. After Handshake
// completes, ReadApp/WriteApp carry inner EAP.
type Tunnel struct {
	mu      sync.Mutex
	in      *bytePipe
	out     *bytePipe
	conn    *tls.Conn
	hsErr   error
	hsDone  bool
	closed  bool
	frag    []byte
	pending [][]byte
}

// NewTunnel starts tls.Server on an in-memory pipe. Handshake runs in the
// background and blocks until the peer finishes or the deadline fires.
func (s *Server) NewTunnel() (*Tunnel, error) {
	if s == nil || s.cfg == nil {
		return nil, errors.New("peap: nil server")
	}
	in, out := newBytePipe(), newBytePipe()
	conn := tls.Server(&duplex{r: in, w: out}, s.cfg.Clone())
	t := &Tunnel{in: in, out: out, conn: conn}
	go t.handshake()
	return t, nil
}

func (t *Tunnel) handshake() {
	_ = t.conn.SetDeadline(time.Now().Add(30 * time.Second))
	err := t.conn.Handshake()
	t.mu.Lock()
	t.hsErr = err
	t.hsDone = err == nil
	t.mu.Unlock()
}

// PushClient appends peer TLS records (one PEAP body, already defragmented).
func (t *Tunnel) PushClient(records []byte) error {
	if t == nil {
		return errors.New("peap: nil tunnel")
	}
	if len(records) == 0 {
		return nil
	}
	_, err := t.in.Write(records)
	return err
}

// PullServer returns and clears buffered server TLS records.
func (t *Tunnel) PullServer() []byte {
	if t == nil {
		return nil
	}
	return t.out.Take()
}

// HandshakeComplete reports a successful TLS 1.3 handshake.
func (t *Tunnel) HandshakeComplete() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hsDone
}

// HandshakeErr is the background handshake error, if any.
func (t *Tunnel) HandshakeErr() error {
	if t == nil {
		return errors.New("peap: nil tunnel")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hsErr
}

// WaitProgress waits until handshake completes or server records appear.
func (t *Tunnel) WaitProgress(d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if t.HandshakeComplete() {
			return
		}
		if t.out.peekLen() > 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// WriteApp writes inner EAP as TLS application data. Handshake must be done.
func (t *Tunnel) WriteApp(p []byte) error {
	if t == nil || t.conn == nil {
		return errors.New("peap: nil tunnel")
	}
	if !t.HandshakeComplete() {
		return errors.New("peap: handshake incomplete")
	}
	_, err := t.conn.Write(p)
	return err
}

// ReadApp reads one inner EAP blob. Handshake must be done.
func (t *Tunnel) ReadApp(timeout time.Duration) ([]byte, error) {
	if t == nil || t.conn == nil {
		return nil, errors.New("peap: nil tunnel")
	}
	if !t.HandshakeComplete() {
		return nil, errors.New("peap: handshake incomplete")
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	_ = t.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, err := t.conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// BufferFragment appends a More-fragments PEAP body. Complete is false
// until a body without M arrives.
func (t *Tunnel) BufferFragment(p Payload) (complete []byte, done bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.frag = append(t.frag, p.TLSData...)
	if p.MoreFragments {
		return nil, false
	}
	out := t.frag
	t.frag = nil
	return out, true
}

// QueueFlight fragments tlsRec and returns the first PEAP body.
func (t *Tunnel) QueueFlight(tlsRec []byte) []byte {
	if t == nil {
		return Encode(Payload{Version: Version0})
	}
	parts := EncodeFlight(tlsRec)
	if len(parts) == 0 {
		return Encode(Payload{Version: Version0})
	}
	t.mu.Lock()
	t.pending = parts[1:]
	t.mu.Unlock()
	return parts[0]
}

// NextFragment returns the next queued PEAP body, if any.
func (t *Tunnel) NextFragment() ([]byte, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pending) == 0 {
		return nil, false
	}
	p := t.pending[0]
	t.pending = t.pending[1:]
	return p, true
}

// Close tears down the TLS session.
func (t *Tunnel) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()
	_ = t.conn.Close()
	_ = t.in.Close()
	_ = t.out.Close()
}
