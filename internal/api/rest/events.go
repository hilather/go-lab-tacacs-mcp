package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
)

// ClearWriteDeadline drops the http.Server write deadline so long-lived
// SSE / listen responses are not killed by listeners.http.write_timeout.
func ClearWriteDeadline(w http.ResponseWriter) error {
	return http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

func (s *Server) heartbeat() time.Duration {
	wt, it := s.WriteTimeout, s.IdleTimeout
	if wt <= 0 {
		wt = 30 * time.Second
	}
	if it <= 0 {
		it = 60 * time.Second
	}
	cap := 15 * time.Second
	m := wt
	if it < m {
		m = it
	}
	if cap < m {
		m = cap
	}
	d := m / 2
	if d <= 0 {
		d = time.Millisecond
	}
	return d
}

func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) {
	rid := requestIDFrom(r)
	if s.Registry == nil {
		writeProblemID(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized"), rid)
		return
	}
	actor, snap, err := s.authenticate(r, false)
	if err != nil {
		if lerr := s.limit(operations.Actor{}, snap); lerr != nil {
			writeDomainID(w, lerr, rid)
			return
		}
		writeDomainID(w, err, rid)
		return
	}
	if err := s.limit(actor, snap); err != nil {
		writeDomainID(w, err, rid)
		return
	}
	if _, err := s.Registry.Invoke(r.Context(), operations.IDEventsSubscribe, snap, operations.Input{Actor: actor}); err != nil {
		writeDomainID(w, err, rid)
		return
	}
	if err := ClearWriteDeadline(w); err != nil && s.Logger != nil {
		s.Logger.Info("rest sse deadline", "err", err, "request_id", rid)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}

	want := categorySet(r.URL.Query()["category"])
	sensitive := auth.Has(actor.Scopes, "events:sensitive")
	lastEventHdr := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	after, err := decodeLastEventID(lastEventHdr)
	if err != nil {
		after = 0
	}

	var sub <-chan events.Event
	var cancel func()
	if s.Events != nil {
		sub, cancel = s.Events.Subscribe(16)
		defer cancel()
	}

	last := after
	if s.Events != nil && lastEventHdr != "" {
		page := s.Events.Read(events.Query{AfterID: after, Limit: events.MaxLimit, Categories: r.URL.Query()["category"]})
		if page.Reset {
			writeSSE(w, "0", "reset", map[string]any{"reset": true, "overwritten": page.Overwritten})
			flush()
		}
		for _, ev := range page.Items {
			if !categoryOK(want, ev.Category) {
				continue
			}
			writeSSE(w, strconv.FormatUint(ev.ID, 10), "", operations.ViewEvent(ev, sensitive))
			last = ev.ID
		}
		flush()
	}

	// First comment so clients and write-timeout tests observe an immediate frame.
	_, _ = io.WriteString(w, ": keepalive\n\n")
	flush()

	tick := time.NewTicker(s.heartbeat())
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			flush()
		case ev, ok := <-subOrNil(sub):
			if !ok {
				sub = nil
				continue
			}
			if ev.ID <= last || !categoryOK(want, ev.Category) {
				continue
			}
			writeSSE(w, strconv.FormatUint(ev.ID, 10), "", operations.ViewEvent(ev, sensitive))
			last = ev.ID
			flush()
		}
	}
}

func subOrNil(ch <-chan events.Event) <-chan events.Event {
	if ch == nil {
		return nil
	}
	return ch
}

func writeSSE(w http.ResponseWriter, id, event string, data any) {
	if id != "" {
		_, _ = io.WriteString(w, "id: "+id+"\n")
	}
	if event != "" {
		_, _ = io.WriteString(w, "event: "+event+"\n")
	}
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			return
		}
		_, _ = io.WriteString(w, "data: ")
		_, _ = w.Write(raw)
		_, _ = io.WriteString(w, "\n")
	}
	_, _ = io.WriteString(w, "\n")
}

func decodeLastEventID(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" {
		return 0, nil
	}
	if n, err := events.DecodeCursor(raw); err == nil && (strings.HasPrefix(raw, "evt_") || raw == "") {
		return n, nil
	}
	return strconv.ParseUint(raw, 10, 64)
}

func categorySet(in []string) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for _, c := range in {
		if c != "" {
			out[c] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func categoryOK(want map[string]struct{}, got string) bool {
	if want == nil {
		return true
	}
	_, ok := want[got]
	return ok
}
