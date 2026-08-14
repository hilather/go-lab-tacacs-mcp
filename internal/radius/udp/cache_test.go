package udp

import (
	"bytes"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

func TestCacheHitPendingPurge(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	c := newCache(8, 4096, 15*time.Second, func() time.Time { return now })
	key := slotKey{
		endpointID: "ep",
		role:       domain.RoleAccess,
		src:        "127.0.0.1:4242",
		listenerID: "radius_access",
		code:       codec.CodeAccessRequest,
		id:         9,
	}
	a := fingerprintOf(bytes.Repeat([]byte{1}, 20))
	b := fingerprintOf(bytes.Repeat([]byte{2}, 20))

	if got, _ := c.Begin(key, a); got != LookupMiss {
		t.Fatalf("first begin=%v", got)
	}
	if got, _ := c.Begin(key, a); got != LookupPending {
		t.Fatalf("pending=%v", got)
	}
	reply := []byte("reply-a")
	c.Complete(key, a, reply)
	got, cached := c.Begin(key, a)
	if got != LookupHit || !bytes.Equal(cached, reply) {
		t.Fatalf("hit=%v cached=%q", got, cached)
	}

	if got, _ = c.Begin(key, b); got != LookupMiss {
		t.Fatalf("purge then miss=%v", got)
	}
	c.Complete(key, b, []byte("reply-b"))
	got, cached = c.Begin(key, b)
	if got != LookupHit || string(cached) != "reply-b" {
		t.Fatalf("after purge hit=%v %q", got, cached)
	}
}

func TestCacheAbandonAndExpiryAndSaturation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	c := newCache(1, 4096, 5*time.Second, func() time.Time { return now })
	k1 := slotKey{endpointID: "a", role: domain.RoleAccess, src: "1", listenerID: "l", code: 1, id: 1}
	k2 := slotKey{endpointID: "b", role: domain.RoleAccess, src: "2", listenerID: "l", code: 1, id: 2}
	fp := fingerprintOf([]byte("declared-packet-bytes!!"))

	if got, _ := c.Begin(k1, fp); got != LookupMiss {
		t.Fatal(got)
	}
	if got, _ := c.Begin(k2, fp); got != LookupSaturated {
		t.Fatalf("saturated=%v", got)
	}
	c.Abandon(k1, fp)
	if got, _ := c.Begin(k1, fp); got != LookupMiss {
		t.Fatalf("after abandon=%v", got)
	}
	c.Complete(k1, fp, []byte("x"))
	now = now.Add(6 * time.Second)
	if got, _ := c.Begin(k1, fp); got != LookupMiss {
		t.Fatalf("expired=%v", got)
	}
}

func BenchmarkCacheHit(b *testing.B) {
	c := newCache(10000, 4<<20, 15*time.Second, time.Now)
	key := slotKey{endpointID: "ep", role: domain.RoleAccess, src: "127.0.0.1:1", listenerID: "radius_access", code: 1, id: 1}
	fp := fingerprintOf(bytes.Repeat([]byte{3}, 40))
	c.Begin(key, fp)
	c.Complete(key, fp, bytes.Repeat([]byte{4}, 40))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got, _ := c.Begin(key, fp); got != LookupHit {
			b.Fatal(got)
		}
	}
}
