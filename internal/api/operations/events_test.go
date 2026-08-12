package operations

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
)

func TestListEventsCursorAndRedaction(t *testing.T) {
	t.Parallel()
	ring := events.New(8, nil)
	for _, ev := range []events.Event{
		{Category: events.CategoryAcct, Type: "start", UserID: "lab-admin", Command: "configure", TaskID: "t1"},
		{Category: events.CategoryAuthen, Type: "ascii_login", UserID: "lab-admin", Result: "pass"},
		{Category: events.CategoryAcct, Type: "stop", UserID: "lab-admin", Arguments: []events.EventAV{
			{Name: "cmd", Separator: "=", Value: "show"},
		}},
	} {
		if ring.Accept(ev).ID == 0 {
			t.Fatal("accept")
		}
	}
	reg, err := New(mustSpec(t), Deps{Events: ring})
	if err != nil {
		t.Fatal(err)
	}
	reader := Actor{ID: "r", Scopes: []string{"events:read"}}
	res, err := reg.Invoke(context.Background(), IDEventsList, mustSnap(t, smallYAML), Input{
		Actor:   reader,
		Request: ListEventsRequest{Limit: 2, Categories: []string{events.CategoryAcct}},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := res.Data.(EventList)
	if len(page.Items) != 2 {
		t.Fatalf("page=%+v", page)
	}
	if page.Items[0].Type != "start" || page.Items[1].Type != "stop" {
		t.Fatalf("filter=%+v", page.Items)
	}
	if page.Items[0].UserID != "" || page.Items[0].Command != "" {
		t.Fatalf("redacted fields leaked: %+v", page.Items[0])
	}
	if len(page.Items[1].Arguments) != 1 || page.Items[1].Arguments[0].Value != "" {
		t.Fatalf("cmd value should be redacted: %+v", page.Items[1].Arguments)
	}

	sens := Actor{ID: "s", Scopes: []string{"events:read", "events:sensitive"}}
	full, err := reg.Invoke(context.Background(), IDEventsList, mustSnap(t, smallYAML), Input{
		Actor:   sens,
		Request: ListEventsRequest{Limit: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := full.Data.(EventList)
	if got.Items[0].UserID != "lab-admin" || got.Items[0].Command != "configure" {
		t.Fatalf("sensitive=%+v", got.Items[0])
	}

	paged := EventList{}
	first, err := reg.Invoke(context.Background(), IDEventsList, mustSnap(t, smallYAML), Input{
		Actor:   reader,
		Request: ListEventsRequest{Limit: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	paged = first.Data.(EventList)
	if paged.NextCursor == nil {
		t.Fatal("expected next cursor")
	}
	second, err := reg.Invoke(context.Background(), IDEventsList, mustSnap(t, smallYAML), Input{
		Actor:   reader,
		Request: ListEventsRequest{Cursor: *paged.NextCursor, Limit: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	rest := second.Data.(EventList)
	if len(rest.Items) != 2 {
		t.Fatalf("page2=%+v", rest)
	}
}

func TestListEventsRequiresScope(t *testing.T) {
	t.Parallel()
	reg, err := New(mustSpec(t), Deps{Events: events.New(4, nil)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Invoke(context.Background(), IDEventsList, mustSnap(t, smallYAML), Input{Actor: reader})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("err=%v", err)
	}
	_, err = reg.Invoke(context.Background(), IDEventsList, mustSnap(t, smallYAML), Input{
		Actor:   Actor{ID: "r", Scopes: []string{"events:read"}},
		Request: ListEventsRequest{Cursor: "nope"},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("cursor err=%v", err)
	}
}

func TestListEventsResetWhenCursorEvicted(t *testing.T) {
	t.Parallel()
	ring := events.New(2, nil)
	ring.Accept(events.Event{Category: events.CategoryAcct, Type: "a"})
	first := ring.Accept(events.Event{Category: events.CategoryAcct, Type: "b"})
	cur := events.EncodeCursor(first.ID)
	ring.Accept(events.Event{Category: events.CategoryAcct, Type: "c"})
	ring.Accept(events.Event{Category: events.CategoryAcct, Type: "d"})
	reg, err := New(mustSpec(t), Deps{Events: ring})
	if err != nil {
		t.Fatal(err)
	}
	res, err := reg.Invoke(context.Background(), IDEventsList, mustSnap(t, smallYAML), Input{
		Actor:   Actor{ID: "r", Scopes: []string{"events:read"}},
		Request: ListEventsRequest{Cursor: cur},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := res.Data.(EventList)
	if page.Reset {
		t.Fatalf("contiguous cursor should not reset: %+v", page)
	}
	ring.Accept(events.Event{Category: events.CategoryAcct, Type: "e"})
	res, err = reg.Invoke(context.Background(), IDEventsList, mustSnap(t, smallYAML), Input{
		Actor:   Actor{ID: "r", Scopes: []string{"events:read"}},
		Request: ListEventsRequest{Cursor: events.EncodeCursor(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	page = res.Data.(EventList)
	if !page.Reset {
		t.Fatalf("expected reset: %+v", page)
	}
}
