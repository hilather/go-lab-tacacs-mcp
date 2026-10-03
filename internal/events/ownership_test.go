package events

import (
	"sync"
	"testing"
	"time"
)

func TestEventOwnership(t *testing.T) {
	r := New(10, nil)
	a, _, ca := r.Subscribe(10)
	defer ca()
	b, _, cb := r.Subscribe(10)
	defer cb()
	start := time.Unix(1, 0)
	stop := time.Unix(2, 0)
	input := Event{Arguments: []EventAV{{Value: "original"}}, StartTime: &start, StopTime: &stop}
	accepted := r.Accept(input)
	input.Arguments[0].Value = "input"
	start = time.Unix(3, 0)
	accepted.Arguments[0].Value = "return"
	*accepted.StopTime = time.Unix(4, 0)
	first := <-a
	first.Arguments[0].Value = "subscriber"
	*first.StartTime = time.Unix(5, 0)
	readers := []Event{<-b, r.Snapshot()[0], r.Read(Query{}).Items[0]}
	latest, _ := r.Latest()
	readers = append(readers, latest)
	for _, e := range readers {
		if e.Arguments[0].Value != "original" || e.StartTime.Unix() != 1 || e.StopTime.Unix() != 2 {
			t.Fatalf("event aliases another owner: %+v", e)
		}
		e.Arguments[0].Value = "reader"
		*e.StopTime = time.Unix(6, 0)
	}
	latest, _ = r.Latest()
	if latest.Arguments[0].Value != "original" || latest.StopTime.Unix() != 2 {
		t.Fatal("reader mutated history")
	}
}

func TestConcurrentFanoutOrdered(t *testing.T) {
	const n = 1000
	r := New(n, nil)
	ch, dropped, cancel := r.Subscribe(n)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.Accept(Event{}) }()
	}
	wg.Wait()
	for id := uint64(1); id <= n; id++ {
		select {
		case e := <-ch:
			if e.ID != id {
				t.Fatalf("got ID %d want %d", e.ID, id)
			}
		case <-dropped:
			t.Fatal("unexpected drop")
		}
	}
}

func TestSubscriptionAdmission(t *testing.T) {
	r := New(1000, nil)
	cancels := make([]func(), 0, MaxSubscribers)
	for i := 0; i < MaxSubscribers; i++ {
		_, _, cancel, err := r.TrySubscribe(1)
		if err != nil {
			t.Fatal(err)
		}
		cancels = append(cancels, cancel)
	}
	if _, _, _, err := r.TrySubscribe(1); err != ErrSubscriptionCapacity {
		t.Fatalf("saturation: %v", err)
	}
	cancels[0]()
	cancels[0]()
	_, _, cancel, err := r.TrySubscribe(1)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for _, c := range cancels {
		c()
	}
	r.Close()
	if _, _, _, err := r.TrySubscribe(1); err == nil {
		t.Fatal("closed ring admitted subscriber")
	}
}

func TestDroppedSubscriptionRetainsAdmissionUntilCancel(t *testing.T) {
	r := New(1000, nil)
	cancels := make([]func(), 0, MaxSubscribers)
	for i := 0; i < MaxSubscribers; i++ {
		_, _, cancel, err := r.TrySubscribe(1)
		if err != nil {
			t.Fatal(err)
		}
		cancels = append(cancels, cancel)
	}
	r.Accept(Event{})
	r.Accept(Event{})
	if _, _, _, err := r.TrySubscribe(1); err != ErrSubscriptionCapacity {
		t.Fatalf("detached handlers evaded admission: %v", err)
	}
	cancels[0]()
	_, _, cancel, err := r.TrySubscribe(1)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for _, c := range cancels {
		c()
	}
}

func TestConcurrentIndependentEventReaders(t *testing.T) {
	r := New(100, nil)
	now := time.Unix(1, 0)
	r.Accept(Event{Arguments: []EventAV{{Value: "original"}}, StartTime: &now, StopTime: &now})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ev := r.Read(Query{}).Items[0]
				ev.Arguments[0].Value = "mutated"
				*ev.StartTime = time.Unix(2, 0)
				*ev.StopTime = time.Unix(3, 0)
			}
		}()
	}
	wg.Wait()
	ev, _ := r.Latest()
	if ev.Arguments[0].Value != "original" || ev.StartTime.Unix() != 1 || ev.StopTime.Unix() != 1 {
		t.Fatal("concurrent readers mutated history")
	}
}

func TestSubscribeFailedAdmissionChannelsClosed(t *testing.T) {
	closed := New(1, nil)
	closed.Close()
	full := New(1, nil)
	for i := 0; i < MaxSubscribers; i++ {
		_, _, cancel, err := full.TrySubscribe(1)
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()
	}
	for _, r := range []*Ring{nil, closed, full} {
		ch, drop, cancel := r.Subscribe(1)
		cancel()
		select {
		case _, ok := <-ch:
			if ok {
				t.Fatal("failed admission event channel open")
			}
		default:
			t.Fatal("failed admission event channel blocks")
		}
		select {
		case <-drop:
		default:
			t.Fatal("failed admission drop channel blocks")
		}
	}
}
