package events

import "testing"

func BenchmarkAccept(b *testing.B) {
	r := New(10000, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Accept(Event{Category: "acct", Type: "start", Result: "success"})
	}
}
