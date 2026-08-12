package events

import "testing"

func BenchmarkAccept(b *testing.B) {
	r := New(10000, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Accept(Event{Category: "acct", Type: "start", Result: "success"})
	}
}

func BenchmarkEventAppend(b *testing.B) {
	r := New(10000, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Accept(Event{Category: CategoryAcct, Type: "start", Result: "success"})
	}
}

func BenchmarkEventReadPage(b *testing.B) {
	r := New(10000, nil)
	for i := 0; i < 1000; i++ {
		r.Accept(Event{Category: CategoryAcct, Type: "start", Result: "success"})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Read(Query{Limit: 50, Categories: []string{CategoryAcct}})
	}
}
