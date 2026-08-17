package tls

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

func TestReadPacketDoesNotStitch(t *testing.T) {
	t.Parallel()
	first := makeRADIUS(t, 40)
	second := makeRADIUS(t, 28)
	var buf bytes.Buffer
	buf.Write(first)
	buf.Write(second)
	got, err := ReadPacket(&buf, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("first packet mutated or stitched: %d", len(got))
	}
	got2, err := ReadPacket(&buf, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, second) {
		t.Fatalf("second packet = %d", len(got2))
	}
}

func TestReadPacketRejectsOversize(t *testing.T) {
	t.Parallel()
	pkt := makeRADIUS(t, 40)
	binary.BigEndian.PutUint16(pkt[2:4], 5000)
	_, err := ReadPacket(bytes.NewReader(pkt), 4096)
	if err != ErrInvalidStreamLength {
		t.Fatalf("got %v", err)
	}
}

func TestReadPacketEOF(t *testing.T) {
	t.Parallel()
	_, err := ReadPacket(bytes.NewReader(nil), 4096)
	if err != io.EOF {
		t.Fatalf("got %v", err)
	}
}

func makeRADIUS(t *testing.T, n int) []byte {
	t.Helper()
	if n < codec.MinPacketBytes {
		t.Fatal("too short")
	}
	b := make([]byte, n)
	b[0] = byte(codec.CodeAccessRequest)
	b[1] = 1
	binary.BigEndian.PutUint16(b[2:4], uint16(n))
	return b
}
