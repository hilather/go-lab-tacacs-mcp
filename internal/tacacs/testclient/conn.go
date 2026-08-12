package testclient

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

// Conn is an independent TACACS+ test client. It uses the testclient codec
// only and must not import the server codec package.
type Conn struct {
	nc      net.Conn
	key     []byte
	writeMu sync.Mutex
	readMu  sync.Mutex
}

// Dial opens a TCP connection to addr. key is the legacy shared secret;
// a nil key leaves bodies in the clear (and requires the unencrypted flag).
func Dial(addr string, key []byte) (*Conn, error) {
	nc, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	return New(nc, key), nil
}

// New wraps an existing connection.
func New(nc net.Conn, key []byte) *Conn {
	return &Conn{nc: nc, key: append([]byte(nil), key...)}
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	if c == nil || c.nc == nil {
		return nil
	}
	return c.nc.Close()
}

// WritePacket encodes h+body, optionally obfuscates, and writes one packet.
func (c *Conn) WritePacket(h codec.Header, body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	out := body
	if len(body) > 0 && h.Flags&codec.FlagUnencrypted == 0 && len(c.key) > 0 {
		out = codec.Obfuscate(h.SessionID, h.Version, h.SeqNo, c.key, body)
	}
	h.Length = uint32(len(out))
	pkt := append(h.Encode(), out...)
	_ = c.nc.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := c.nc.Write(pkt)
	return err
}

// ReadPacket reads one header and body, then deobfuscates when required.
func (c *Conn) ReadPacket() (codec.Header, []byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	_ = c.nc.SetReadDeadline(time.Now().Add(2 * time.Second))
	var raw [codec.HeaderSize]byte
	if _, err := io.ReadFull(c.nc, raw[:]); err != nil {
		return codec.Header{}, nil, err
	}
	h, err := codec.DecodeHeader(raw[:])
	if err != nil {
		return codec.Header{}, nil, err
	}
	body, err := h.AllocateBody(codec.MaxBodyBytes)
	if err != nil {
		return h, nil, err
	}
	if len(body) > 0 {
		if _, err := io.ReadFull(c.nc, body); err != nil {
			return h, nil, err
		}
		if h.Flags&codec.FlagUnencrypted == 0 && len(c.key) > 0 {
			body = codec.Obfuscate(h.SessionID, h.Version, h.SeqNo, c.key, body)
		}
	}
	return h, body, nil
}

// SetDeadlines overrides the next I/O deadline.
func (c *Conn) SetDeadlines(d time.Duration) {
	_ = c.nc.SetDeadline(time.Now().Add(d))
}
