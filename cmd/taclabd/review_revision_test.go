package main

import (
	"fmt"
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestSnapshotPublicationsEmitRevisionEvents(t *testing.T) {
	doc, err := config.Parse([]byte("schema_version: 1\nlisteners:\n  secure_tacacs: {enabled: false}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ring := events.New(64, nil)
	t.Cleanup(ring.Close)
	m, err := state.New(doc, state.Options{Hook: newSnapshotObserver(nil, func() *events.Ring { return ring })})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := m.CreateUser(state.CreateUser{ID: fmt.Sprintf("user-%d", i)}, nil); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if _, err = m.CreateUser(state.CreateUser{ID: "user-0"}, nil); err == nil {
		t.Fatal("duplicate mutation succeeded")
	}
	if _, err = m.Reload(doc, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Reset(nil); err != nil {
		t.Fatal(err)
	}
	items := ring.Read(events.Query{Limit: 64}).Items
	if len(items) != 14 {
		t.Fatalf("successful publications=%d events=%d", m.Revision()-1, len(items))
	}
	for i, event := range items {
		if event.Type != "state.revision.changed" || event.Category != events.CategoryConfig || uint64(event.Revision) != uint64(i+2) {
			t.Fatalf("publication event %d=%+v", i, event)
		}
	}
}
