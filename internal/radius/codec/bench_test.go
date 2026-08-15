package codec

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

var (
	benchPacket Packet
	benchBytes  []byte
)

func BenchmarkRadiusHeaderDecode(b *testing.B) {
	raw := minPacket(CodeAccessRequest, 1)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, err := DecodeHeader(raw)
		if err != nil {
			b.Fatal(err)
		}
		benchPacket.Code = h.Code
	}
}

func BenchmarkRadiusPacketDecode_8Attrs(b *testing.B) {
	benchmarkPacketDecode(b, 8)
}

func BenchmarkRadiusPacketDecode_64Attrs(b *testing.B) {
	benchmarkPacketDecode(b, 64)
}

func BenchmarkRadiusPacketEncode(b *testing.B) {
	p := packetWithAttrs(16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, err := Encode(p)
		if err != nil {
			b.Fatal(err)
		}
		benchBytes = raw
	}
}

func benchmarkPacketDecode(b *testing.B, n int) {
	b.Helper()
	raw, err := Encode(packetWithAttrs(n))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := Decode(raw)
		if err != nil {
			b.Fatal(err)
		}
		benchPacket = p
	}
}

func packetWithAttrs(n int) Packet {
	attrs := make(attribute.RawSet, n)
	for i := range attrs {
		attrs[i] = attribute.Raw{Type: 25, Value: []byte{'x'}}
	}
	return Packet{Code: CodeAccessRequest, Identifier: 1, Attributes: attrs}
}
