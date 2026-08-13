package events

import (
	"sync"
	"testing"
)

func TestRaceAcceptReadSubscribe(t *testing.T) {
	r := New(32, nil)
	t.Cleanup(r.Close)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, _, cancel := r.Subscribe(4)
			defer cancel()
			for j := 0; j < 20; j++ {
				r.Accept(Event{Category: CategoryAcct, Type: "start", Result: "success"})
				_ = r.Read(Query{Limit: 5})
				select {
				case <-ch:
				default:
				}
			}
		}()
	}
	wg.Wait()
}
