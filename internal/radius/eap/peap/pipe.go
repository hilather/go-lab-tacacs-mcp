package peap

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// bytePipe is an unbounded in-memory pipe. Writes never block. Reads wait
// for data, close, or deadline.
type bytePipe struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	closed   bool
	deadline time.Time
}

func newBytePipe() *bytePipe {
	p := &bytePipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *bytePipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		if err := p.deadlineErrLocked(); err != nil {
			return 0, err
		}
		if !p.deadline.IsZero() {
			wait := time.Until(p.deadline)
			if wait <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.AfterFunc(wait, func() {
				p.mu.Lock()
				p.cond.Broadcast()
				p.mu.Unlock()
			})
			p.cond.Wait()
			timer.Stop()
			continue
		}
		p.cond.Wait()
	}
	if len(p.buf) == 0 {
		if p.closed {
			return 0, io.EOF
		}
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(b, p.buf)
	p.buf = append([]byte(nil), p.buf[n:]...)
	return n, nil
}

func (p *bytePipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	p.buf = append(p.buf, b...)
	p.cond.Broadcast()
	return len(b), nil
}

func (p *bytePipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.cond.Broadcast()
	}
	return nil
}

func (p *bytePipe) Take() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.buf
	p.buf = nil
	return out
}

func (p *bytePipe) peekLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buf)
}

func (p *bytePipe) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadline = t
	p.cond.Broadcast()
	return nil
}

func (p *bytePipe) deadlineErrLocked() error {
	if p.deadline.IsZero() || time.Now().Before(p.deadline) {
		return nil
	}
	return os.ErrDeadlineExceeded
}

type duplex struct {
	r, w *bytePipe
}

func (d *duplex) Read(b []byte) (int, error)  { return d.r.Read(b) }
func (d *duplex) Write(b []byte) (int, error) { return d.w.Write(b) }
func (d *duplex) Close() error {
	_ = d.r.Close()
	_ = d.w.Close()
	return nil
}
func (d *duplex) LocalAddr() net.Addr                { return pipeAddr("peap-local") }
func (d *duplex) RemoteAddr() net.Addr               { return pipeAddr("peap-remote") }
func (d *duplex) SetDeadline(t time.Time) error      { return d.setDeadline(t, t) }
func (d *duplex) SetReadDeadline(t time.Time) error  { return d.r.SetDeadline(t) }
func (d *duplex) SetWriteDeadline(t time.Time) error { return d.w.SetDeadline(t) }

func (d *duplex) setDeadline(r, w time.Time) error {
	_ = d.r.SetDeadline(r)
	_ = d.w.SetDeadline(w)
	return nil
}

type pipeAddr string

func (a pipeAddr) Network() string { return "peap" }
func (a pipeAddr) String() string  { return string(a) }
