package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const scopeEventsSensitive = "events:sensitive"

func handleListEvents(ring *events.Ring) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		req, _ := in.Request.(ListEventsRequest)
		after, err := events.DecodeCursor(req.Cursor)
		if err != nil {
			return nil, err
		}
		if ring == nil {
			return EventList{Items: []EventView{}, NextCursor: nil}, nil
		}
		page := ring.Read(events.Query{
			AfterID:    after,
			Limit:      req.Limit,
			Categories: req.Categories,
		})
		sensitive := hasScope(in.Actor, scopeEventsSensitive)
		out := EventList{
			Items:       make([]EventView, len(page.Items)),
			Reset:       page.Reset,
			Overwritten: page.Overwritten,
		}
		for i, ev := range page.Items {
			out.Items[i] = viewEvent(ev, sensitive)
		}
		if page.HasMore && page.NextAfterID != 0 {
			cur := events.EncodeCursor(page.NextAfterID)
			out.NextCursor = &cur
		}
		return out, nil
	}
}

func viewEvent(e events.Event, sensitive bool) EventView {
	v := EventView{
		SchemaVersion: e.SchemaVersion,
		ID:            e.ID,
		Time:          e.Time,
		Category:      e.Category,
		Type:          e.Type,
		Result:        e.Result,
		Transport:     e.Transport,
		ClientID:      e.ClientID,
		SessionID:     e.SessionID,
		Revision:      e.Revision,
		TaskID:        e.TaskID,
		StartTime:     e.StartTime,
		StopTime:      e.StopTime,
		AuthenMethod:  e.AuthenMethod,
		AuthenType:    e.AuthenType,
		Service:       e.Service,
		Privilege:     e.Privilege,
		Port:          e.Port,
		Remote:        e.Remote,
	}
	if v.SchemaVersion == 0 {
		v.SchemaVersion = events.SchemaVersion
	}
	if sensitive {
		v.UserID = e.UserID
		v.Command = e.Command
		v.Arguments = copyEventAVs(e.Arguments, true)
	} else {
		v.Arguments = copyEventAVs(e.Arguments, false)
	}
	return v
}

func copyEventAVs(in []events.EventAV, sensitive bool) []EventAV {
	if len(in) == 0 {
		return nil
	}
	out := make([]EventAV, len(in))
	for i, a := range in {
		val := a.Value
		if !sensitive && (a.Name == "cmd" || a.Name == "cmd-arg") {
			val = ""
		}
		out[i] = EventAV{Name: a.Name, Separator: a.Separator, Value: val}
	}
	return out
}

func handleSubscribe(_ context.Context, _ *state.Snapshot, _ Input) (any, error) {
	return EventStream{}, nil
}

func hasScope(actor Actor, scope string) bool {
	for _, s := range actor.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
