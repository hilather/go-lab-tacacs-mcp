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
	if a.SchemaVersion != SchemaVersion {
		t.Fatalf("schema=%d", a.SchemaVersion)
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

func TestOverwriteDoesNotBlockAccept(t *testing.T) {
	t.Parallel()
	r := New(8, domain.SystemClock{})
	start := time.Now()
	for i := 0; i < 64; i++ {
		ev := r.Accept(Event{Category: CategoryAcct, Type: "start", Result: "success"})
		if ev.ID == 0 {
			t.Fatal("overwrite must still accept")
		}
	}
	if time.Since(start) > time.Second {
		t.Fatal("accept blocked under overwrite")
	}
	if r.Len() != 8 || r.Overwritten() != 56 {
		t.Fatalf("len=%d overwritten=%d", r.Len(), r.Overwritten())
	}
}

func TestReadCursorAndReset(t *testing.T) {
	t.Parallel()
	r := New(3, domain.SystemClock{})
	r.Accept(Event{Category: CategoryAcct, Type: "a"})
	r.Accept(Event{Category: CategoryAcct, Type: "b"})
	r.Accept(Event{Category: CategoryAcct, Type: "c"})
	first := r.Read(Query{Limit: 2})
	if len(first.Items) != 2 || first.HasMore != true || first.Reset {
		t.Fatalf("first=%+v", first)
	}
	if first.Items[0].Type != "a" || first.Items[1].Type != "b" {
		t.Fatalf("items=%+v", first.Items)
	}
	next := r.Read(Query{AfterID: first.NextAfterID, Limit: 2})
	if len(next.Items) != 1 || next.Items[0].Type != "c" || next.HasMore || next.Reset {
		t.Fatalf("next=%+v", next)
	}

	r.Accept(Event{Category: CategoryAcct, Type: "d"})
	r.Accept(Event{Category: CategoryAcct, Type: "e"})
	// IDs now 3,4,5 (a,b overwritten). Cursor after 1 is evicted.
	reset := r.Read(Query{AfterID: 1, Limit: 10})
	if !reset.Reset {
		t.Fatalf("expected reset, page=%+v", reset)
	}
	if len(reset.Items) != 3 || reset.Items[0].Type != "c" {
		t.Fatalf("reset items=%+v", reset.Items)
	}

	contig := r.Read(Query{AfterID: 2, Limit: 10})
	if contig.Reset {
		t.Fatalf("after 2 is contiguous with oldest 3: %+v", contig)
	}
}

func TestReadCategoryFilter(t *testing.T) {
	t.Parallel()
	r := New(8, domain.SystemClock{})
	r.Accept(Event{Category: CategoryAcct, Type: "start"})
	r.Accept(Event{Category: CategoryAuthen, Type: "ascii_login"})
	r.Accept(Event{Category: CategoryAcct, Type: "stop"})
	page := r.Read(Query{Categories: []string{CategoryAcct}, Limit: 10})
	if len(page.Items) != 2 || page.Items[0].Type != "start" || page.Items[1].Type != "stop" {
		t.Fatalf("page=%+v", page)
	}
}

func TestReadSkipsSuppressedExport(t *testing.T) {
	t.Parallel()
	r := New(8, domain.SystemClock{})
	r.Accept(Event{Category: CategoryAcct, Type: "hidden", SuppressExport: true})
	r.Accept(Event{Category: CategoryAcct, Type: "visible"})
	page := r.Read(Query{Limit: 10})
	if len(page.Items) != 1 || page.Items[0].Type != "visible" {
		t.Fatalf("page=%+v", page.Items)
	}
	if r.Len() != 2 {
		t.Fatalf("ring must still retain hidden record: %d", r.Len())
	}
}

func TestReadClampsLimit(t *testing.T) {
	t.Parallel()
	r := New(8, domain.SystemClock{})
	for i := 0; i < 5; i++ {
		r.Accept(Event{Category: CategorySystem, Type: "tick"})
	}
	zero := r.Read(Query{})
	if len(zero.Items) != 5 {
		t.Fatalf("default limit should return all 5, got %d", len(zero.Items))
	}
	huge := r.Read(Query{Limit: MaxLimit + 50})
	if len(huge.Items) != 5 {
		t.Fatalf("clamped=%d", len(huge.Items))
	}
}

func TestRejectDoesNotAssignID(t *testing.T) {
	t.Parallel()
	r := New(4, domain.SystemClock{})
	r.SetReject(true)
	got := r.Accept(Event{Type: "x"})
	if got.ID != 0 {
		t.Fatalf("rejected id=%d", got.ID)
	}
	if r.Len() != 0 {
		t.Fatal("rejected event stored")
	}
	r.SetReject(false)
	got = r.Accept(Event{Type: "y"})
	if got.ID != 1 {
		t.Fatalf("id after reject=%d", got.ID)
	}
}

func TestSubscribeDoesNotBlockAccept(t *testing.T) {
	t.Parallel()
	r := New(16, domain.SystemClock{})
	ch, cancel := r.Subscribe(1)
	defer cancel()
	r.Accept(Event{Type: "one"})
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("first event")
	}
	// Fill the subscriber buffer, then overflow must drop the sub, not block.
	r.Accept(Event{Type: "two"})
	done := make(chan struct{})
	go func() {
		r.Accept(Event{Type: "three"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accept blocked on slow subscriber")
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

func TestConcurrentReadAndWrite(t *testing.T) {
	t.Parallel()
	r := New(64, domain.SystemClock{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				r.Accept(Event{Category: CategoryAcct, Type: "start", Result: "success"})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				_ = r.Read(Query{Limit: 10, Categories: []string{CategoryAcct}})
			}
		}()
	}
	wg.Wait()
	if r.Len() != 64 {
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
	if len(r.Read(Query{}).Items) != 0 {
		t.Fatal("nil read")
	}
}
