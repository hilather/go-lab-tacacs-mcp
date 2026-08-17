package tls

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const (
	minPacket = 20
	maxPacket = 4096
)

// ErrInvalidLength is a framing error from the independent client.
var ErrInvalidLength = errors.New("testclient/tls: invalid RADIUS stream length")

// Conn is one TLS 1.3 RadSec client connection.
type Conn struct {
	c *tls.Conn
}

// Dial connects with TLS 1.3 and the supplied client config.
func Dial(addr string, cfg *tls.Config) (*Conn, error) {
	if cfg == nil {
		return nil, errors.New("tls config is required")
	}
	clone := cfg.Clone()
	if clone.MinVersion == 0 {
		clone.MinVersion = tls.VersionTLS13
	}
	if clone.MaxVersion == 0 {
		clone.MaxVersion = tls.VersionTLS13
	}
	d := &tls.Dialer{Config: clone, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("tls dial did not return a tls.Conn")
	}
	return &Conn{c: tc}, nil
}

// WritePacket writes one RADIUS packet using the header Length field.
func (c *Conn) WritePacket(pkt []byte) error {
	if c == nil || c.c == nil {
		return errors.New("closed")
	}
	if len(pkt) < minPacket || len(pkt) > maxPacket {
		return ErrInvalidLength
	}
	if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
		return ErrInvalidLength
	}
	_, err := c.c.Write(pkt)
	return err
}

// ReadPacket reads one RADIUS packet from the stream.
func (c *Conn) ReadPacket() ([]byte, error) {
	if c == nil || c.c == nil {
		return nil, errors.New("closed")
	}
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [4]byte
	if _, err := io.ReadFull(c.c, hdr[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < minPacket || length > maxPacket {
		return nil, ErrInvalidLength
	}
	buf := make([]byte, length)
	copy(buf, hdr[:])
	if _, err := io.ReadFull(c.c, buf[4:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// Close closes the TLS connection.
func (c *Conn) Close() error {
	if c == nil || c.c == nil {
		return nil
	}
	return c.c.Close()
}
