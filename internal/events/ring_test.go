package events

import (
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func TestAcceptAssignsMonotonicIDs(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC)
	r := New(4, fixedClock{t: now})
	a := r.Accept(Event{Category: "acct", Type: "start", Result: "success"})
	b := r.Accept(Event{Category: "acct", Type: "start", Result: "success"})
	if a.ID != 1 || b.ID != 2 {
		t.Fatalf("ids %d %d", a.ID, b.ID)
	}
	if !a.Time.Equal(now) {
		t.Fatalf("time=%v", a.Time)
	}
	if r.Len() != 2 || r.Overwritten() != 0 {
		t.Fatalf("len=%d overwritten=%d", r.Len(), r.Overwritten())
	}
}

func TestOverwriteOldest(t *testing.T) {
	t.Parallel()
	r := New(2, domain.SystemClock{})
	r.Accept(Event{Type: "a"})
	r.Accept(Event{Type: "b"})
	r.Accept(Event{Type: "c"})
	if r.Len() != 2 || r.Overwritten() != 1 {
		t.Fatalf("len=%d overwritten=%d", r.Len(), r.Overwritten())
	}
	got := r.Snapshot()
	if len(got) != 2 || got[0].Type != "b" || got[1].Type != "c" {
		t.Fatalf("snapshot=%+v", got)
	}
	latest, ok := r.Latest()
	if !ok || latest.Type != "c" {
		t.Fatalf("latest=%+v ok=%v", latest, ok)
	}
}

func TestAcceptConcurrent(t *testing.T) {
	t.Parallel()
	r := New(256, domain.SystemClock{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				r.Accept(Event{Category: "acct", Type: "start", Result: "success"})
			}
		}()
	}
	wg.Wait()
	if r.Len() != 256 {
		t.Fatalf("len=%d", r.Len())
	}
}

func TestNilRing(t *testing.T) {
	t.Parallel()
	var r *Ring
	if r.Accept(Event{Type: "x"}).ID != 0 {
		t.Fatal("nil accept")
	}
	if r.Len() != 0 || r.Overwritten() != 0 {
		t.Fatal("nil stats")
	}
	if _, ok := r.Latest(); ok {
		t.Fatal("nil latest")
	}
	if r.Snapshot() != nil {
		t.Fatal("nil snapshot")
	}
}
