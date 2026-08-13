package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
)

type listenNotifications struct {
	ToolsListChanged      bool     `json:"toolsListChanged"`
	PromptsListChanged    bool     `json:"promptsListChanged"`
	ResourcesListChanged  bool     `json:"resourcesListChanged"`
	ResourceSubscriptions []string `json:"resourceSubscriptions"`
}

func handleListen(w http.ResponseWriter, r *http.Request, opts Options, p auth.Principal, req rpcRequest) {
	var params struct {
		Notifications listenNotifications `json:"notifications"`
	}
	if len(req.Params) > 0 {
		dec := json.NewDecoder(bytes.NewReader(req.Params))
		if err := dec.Decode(&params); err != nil {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "invalid listen params"}})
			return
		}
	}

	snap := snapshotOf(opts)
	accepted := listenNotifications{}
	if params.Notifications.ToolsListChanged {
		accepted.ToolsListChanged = true
	}
	if params.Notifications.ResourcesListChanged {
		accepted.ResourcesListChanged = true
	}
	var wantEvents bool
	for _, uri := range params.Notifications.ResourceSubscriptions {
		op, ok := resourceOp(opts.Registry, uri)
		if !ok || !hasScopes(p, op.Scopes) {
			continue
		}
		accepted.ResourceSubscriptions = append(accepted.ResourceSubscriptions, uri)
		if uri == resourceEventsRecent {
			wantEvents = true
		}
	}
	if wantEvents && opts.Registry != nil && snap != nil {
		if _, err := opts.Registry.Invoke(r.Context(), operations.IDEventsSubscribe, snap, operations.Input{Actor: p.Actor()}); err != nil {
			writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: toolRPCError(err)})
			return
		}
	}

	_ = clearWriteDeadline(w)
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

	subID := subscriptionID(req.ID)
	writeSSEJSON(w, map[string]any{
		"jsonrpc": jsonRPCVersion,
		"method":  "notifications/subscriptions/acknowledged",
		"params": map[string]any{
			"_meta":         map[string]any{metaSubscriptionID: subID},
			"notifications": ackFilter(accepted),
		},
	})
	flush()
	_, _ = io.WriteString(w, ": keepalive\n\n")
	flush()

	var sub <-chan events.Event
	var dropped <-chan struct{}
	var cancel func()
	if wantEvents && opts.Events != nil {
		sub, dropped, cancel = opts.Events.Subscribe(16)
		defer cancel()
	}

	var lastRev domain.Revision
	if snap != nil {
		lastRev = snap.Revision
	}

	tick := time.NewTicker(heartbeat(opts.WriteTimeout, opts.IdleTimeout))
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			flush()
			if notifyRevision(w, opts, accepted, subID, &lastRev) {
				flush()
			}
		case <-dropOrNil(dropped):
			writeSSEJSON(w, listenComplete(req.ID, subID))
			flush()
			return
		case ev, ok := <-subOrNil(sub):
			if !ok {
				sub = nil
				continue
			}
			_ = ev
			if wantEvents {
				writeResourceUpdated(w, subID, resourceEventsRecent)
				flush()
			}
			if notifyRevision(w, opts, accepted, subID, &lastRev) {
				flush()
			}
		}
	}
}

func ackFilter(n listenNotifications) map[string]any {
	out := map[string]any{}
	if n.ToolsListChanged {
		out["toolsListChanged"] = true
	}
	if n.ResourcesListChanged {
		out["resourcesListChanged"] = true
	}
	if len(n.ResourceSubscriptions) > 0 {
		out["resourceSubscriptions"] = n.ResourceSubscriptions
	}
	return out
}

func notifyRevision(w http.ResponseWriter, opts Options, accepted listenNotifications, subID any, last *domain.Revision) bool {
	if opts.Snapshot == nil || last == nil {
		return false
	}
	snap := opts.Snapshot()
	if snap == nil || snap.Revision == *last {
		return false
	}
	*last = snap.Revision
	sent := false
	for _, uri := range accepted.ResourceSubscriptions {
		writeResourceUpdated(w, subID, uri)
		sent = true
	}
	return sent
}

func writeResourceUpdated(w http.ResponseWriter, subID any, uri string) {
	writeSSEJSON(w, map[string]any{
		"jsonrpc": jsonRPCVersion,
		"method":  "notifications/resources/updated",
		"params": map[string]any{
			"_meta": map[string]any{metaSubscriptionID: subID},
			"uri":   uri,
		},
	})
}

func listenComplete(id json.RawMessage, subID any) map[string]any {
	return map[string]any{
		"jsonrpc": jsonRPCVersion,
		"id":      jsonRaw(id),
		"result": map[string]any{
			"resultType": resultTypeComplete,
			"_meta":      map[string]any{metaSubscriptionID: subID},
		},
	}
}

func jsonRaw(id json.RawMessage) any {
	var v any
	if err := json.Unmarshal(id, &v); err != nil {
		return nil
	}
	return v
}

func subscriptionID(id json.RawMessage) any {
	return jsonRaw(id)
}

func heartbeat(writeTimeout, idleTimeout time.Duration) time.Duration {
	wt, it := writeTimeout, idleTimeout
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

func clearWriteDeadline(w http.ResponseWriter) error {
	return http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

func subOrNil(ch <-chan events.Event) <-chan events.Event {
	if ch == nil {
		return nil
	}
	return ch
}

func dropOrNil(ch <-chan struct{}) <-chan struct{} {
	if ch == nil {
		return nil
	}
	return ch
}

func writeSSEJSON(w http.ResponseWriter, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = io.WriteString(w, "data: ")
	_, _ = w.Write(raw)
	_, _ = io.WriteString(w, "\n\n")
}
