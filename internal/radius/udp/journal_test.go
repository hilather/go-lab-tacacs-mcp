package udp

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
)

func TestJournalSeenRememberExpirySaturation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 18, 0, 0, 0, time.UTC)
	j := newJournal(2, 1024, 5*time.Second, func() time.Time { return now })
	k1 := server.JournalKey{EndpointID: "ep", SrcIP: "192.0.2.1", SrcPort: 1, SessionID: "a", StatusType: "start"}
	k2 := server.JournalKey{EndpointID: "ep", SrcIP: "192.0.2.1", SrcPort: 1, SessionID: "b", StatusType: "start"}
	k3 := server.JournalKey{EndpointID: "ep", SrcIP: "192.0.2.1", SrcPort: 1, SessionID: "c", StatusType: "start"}

	if j.Seen(k1) {
		t.Fatal("empty journal")
	}
	if !j.Remember(k1) || !j.Seen(k1) {
		t.Fatal("remember k1")
	}
	if got := j.len(); got != 1 {
		t.Fatalf("len after k1=%d", got)
	}
	if !j.Remember(k2) {
		t.Fatal("remember k2")
	}
	if got := j.len(); got != 2 {
		t.Fatalf("len after k2=%d", got)
	}
	if j.Remember(k3) {
		t.Fatal("third entry must saturate")
	}
	if j.saturations() != 1 {
		t.Fatalf("sat=%d", j.saturations())
	}
	if j.Seen(k3) {
		t.Fatal("saturated key must not be stored")
	}
	if got := j.len(); got != 2 {
		t.Fatalf("sat must not store k3, len=%d", got)
	}

	now = now.Add(6 * time.Second)
	seenK1 := j.Seen(k1)
	seenK2 := j.Seen(k2)
	if seenK1 || seenK2 {
		t.Fatal("expired keys still visible")
	}
	if got := j.len(); got != 0 {
		t.Fatalf("expired entries must be dropped, len=%d", got)
	}
	if !j.Remember(k3) {
		t.Fatal("after expiry must accept")
	}
	if got := j.len(); got != 1 {
		t.Fatalf("len after k3=%d", got)
	}
}

func TestJournalByteSaturation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 18, 0, 0, 0, time.UTC)
	k := server.JournalKey{EndpointID: "ep", SessionID: "sess", StatusType: "start"}
	j := newJournal(100, journalKeyBytes(k)-1, time.Minute, func() time.Time { return now })
	if j.Remember(k) {
		t.Fatal("over-budget key must saturate")
	}
	if j.saturations() != 1 {
		t.Fatalf("sat=%d", j.saturations())
	}
}

func TestMinuteSamplerWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 18, 0, 30, 0, time.UTC)
	s := newMinuteSampler(2, func() time.Time { return now })
	first := s.Allow()
	second := s.Allow()
	third := s.Allow()
	if !first || !second || third {
		t.Fatal("limit 2")
	}
	now = now.Add(time.Minute)
	if !s.Allow() {
		t.Fatal("next minute resets")
	}
	zero := newMinuteSampler(0, func() time.Time { return now })
	if zero.Allow() {
		t.Fatal("limit 0 must not record")
	}
}

func BenchmarkJournalRemember(b *testing.B) {
	j := newJournal(20000, 8<<20, time.Minute, time.Now)
	k := server.JournalKey{EndpointID: "ep", SrcIP: "192.0.2.1", SrcPort: 9, SessionID: "s", StatusType: "start"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.SrcPort = uint16(i)
		_ = j.Remember(k)
	}
}
