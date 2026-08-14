package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
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
		q, err := req.RingQuery(after)
		if err != nil {
			return nil, err
		}
		page := ring.Read(q)
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

// ViewEvent is the adapter-facing redaction of a ring event.
func ViewEvent(e events.Event, sensitive bool) EventView {
	return viewEvent(e, sensitive)
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
		Protocol:      e.Protocol,
		Carrier:       e.Carrier,
		ListenerRole:  e.ListenerRole,
		ListenerID:    e.ListenerID,
		PacketCode:    e.PacketCode,
		Outcome:       e.Outcome,
		ReasonCode:    e.ReasonCode,
		EndpointID:    e.EndpointID,
	}
	if v.SchemaVersion == 0 {
		v.SchemaVersion = events.SchemaVersion
	}
	if sensitive {
		v.UserID = e.UserID
		v.Command = e.Command
		v.AcctSessionID = e.AcctSessionID
		v.Arguments = copyEventAVs(e.Arguments, true)
	} else {
		v.Arguments = copyEventAVs(e.Arguments, false)
	}
	return v
}

// RingQuery maps list/subscribe filters onto the ring query. Invalid
// protocol or listener_role values fail closed.
func (r ListEventsRequest) RingQuery(after uint64) (events.Query, error) {
	if r.Protocol != "" {
		if _, err := domain.ParseProtocol(r.Protocol); err != nil {
			return events.Query{}, err
		}
	}
	if r.ListenerRole != "" {
		if _, err := domain.ParseListenerRole(r.ListenerRole); err != nil {
			return events.Query{}, err
		}
	}
	return events.Query{
		AfterID:      after,
		Limit:        r.Limit,
		Categories:   r.Categories,
		Protocol:     r.Protocol,
		ListenerRole: r.ListenerRole,
		PacketCode:   r.PacketCode,
		Outcome:      r.Outcome,
	}, nil
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
