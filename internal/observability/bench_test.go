package observability

import "testing"

func BenchmarkRecorderInc(b *testing.B) {
	rec := NewRecorder(NewRegistry())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.Authen(TransportLegacy, "ascii", "pass")
	}
}

func BenchmarkWritePrometheus(b *testing.B) {
	reg := NewRegistry()
	rec := NewRecorder(reg)
	for i := 0; i < 32; i++ {
		rec.Authen(TransportLegacy, "ascii", "pass")
		rec.API("system.status.get", ResultSuccess, "none", 0.001)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reg.WritePrometheus(discard{})
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
