package codec

import "testing"

var (
	benchHeader Header
	benchBytes  []byte
)

func BenchmarkHeaderDecode(b *testing.B) {
	raw := []byte{0xc0, TypeAuthen, 1, 0, 0x01, 0x02, 0x03, 0x04, 0, 0, 0, 32}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, err := DecodeHeader(raw)
		if err != nil {
			b.Fatal(err)
		}
		benchHeader = h
	}
}

func BenchmarkHeaderEncode(b *testing.B) {
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, SessionID: 0x01020304, Length: 32}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchBytes = h.Encode()
	}
}

func BenchmarkLegacyObfuscate_64B(b *testing.B) {
	benchmarkObfuscate(b, 64)
}

func BenchmarkLegacyObfuscate_1KiB(b *testing.B) {
	benchmarkObfuscate(b, 1024)
}

func BenchmarkAuthenStartDecode(b *testing.B) {
	raw, err := (AuthenStart{
		Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServiceLogin,
		User: []byte("admin"), Port: []byte("tty"), RemAddr: []byte("127.0.0.1"),
	}).Encode()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeAuthenStart(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthorDecode_16Args(b *testing.B) {
	benchmarkAuthorDecode(b, 16)
}

func BenchmarkAuthorDecode_255Args(b *testing.B) {
	benchmarkAuthorDecode(b, 255)
}

func benchmarkAuthorDecode(b *testing.B, n int) {
	b.Helper()
	args := make([]Argument, n)
	for i := range args {
		args[i] = Argument{Name: "a", Separator: '=', Value: "b"}
	}
	raw, err := (AuthorRequest{
		AuthenMethod: AuthenMethodTACACS,
		User:         []byte("admin"),
		Args:         args,
	}).Encode()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeAuthorRequest(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkObfuscate(b *testing.B, n int) {
	b.Helper()
	key := []byte("lab-test-shared-secret")
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
