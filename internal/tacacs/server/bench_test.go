package server

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

func BenchmarkDispatchAuthorPerConnection(b *testing.B) {
	benchmarkDispatch(b, false)
}

func BenchmarkDispatchAuthorSingleConnect(b *testing.B) {
	benchmarkDispatch(b, true)
}

func benchmarkDispatch(b *testing.B, single bool) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, done := startServe(testLimits())
		flags := byte(0)
		if single {
			flags = codec.FlagSingleConnect
		}
		h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, Flags: flags, SessionID: 1}
		if err := writePacket(client, h, authorBody("bench")); err != nil {
			b.Fatal(err)
		}
		if _, _, err := readPacket(client); err != nil {
			b.Fatal(err)
		}
		if single {
			h2 := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 2}
			if err := writePacket(client, h2, authorBody("bench")); err != nil {
				b.Fatal(err)
			}
			if _, _, err := readPacket(client); err != nil {
				b.Fatal(err)
			}
		}
		_ = client.Close()
		<-done
	}
}
