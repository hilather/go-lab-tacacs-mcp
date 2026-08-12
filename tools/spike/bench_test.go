package spike

import "testing"

// These benches live only in the evaluation harness. make bench still
// requires Benchmark functions under internal/{tacacs,policy,state}.

func BenchmarkHeaderDecode(b *testing.B) {
	raw := []byte{0xc0, TypeAuthen, 1, 0, 0x01, 0x02, 0x03, 0x04, 0, 0, 0, 32}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeHeader(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHeaderEncode(b *testing.B) {
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, SessionID: 0x01020304, Length: 32}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Encode()
	}
}

func BenchmarkObfuscate64B(b *testing.B) {
	benchmarkObfuscate(b, 64)
}

func BenchmarkObfuscate1KiB(b *testing.B) {
	benchmarkObfuscate(b, 1024)
}

func benchmarkObfuscate(b *testing.B, n int) {
	b.Helper()
	key := []byte("tacacssecret")
	body := make([]byte, n)
	for i := range body {
		body[i] = byte(i)
	}
	b.ReportAllocs()
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Obfuscate(0x01020304, 0xc0, 1, key, body)
	}
}
