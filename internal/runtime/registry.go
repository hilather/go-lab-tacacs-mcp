package runtime

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Registry starts, observes, and stops a variable set of listeners.
type Registry struct {
	listeners []Listener
	byID      map[string]Listener
	started   atomic.Bool
}

// New validates unique IDs and bind conflicts, then stores listeners in
// deterministic ID order. Start is a separate call.
func New(listeners ...Listener) (*Registry, error) {
	if err := validateListeners(listeners); err != nil {
		return nil, err
	}
	sorted := append([]Listener(nil), listeners...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID() < sorted[j].ID()
	})
	byID := make(map[string]Listener, len(sorted))
	for _, l := range sorted {
		byID[l.ID()] = l
	}
	return &Registry{listeners: sorted, byID: byID}, nil
}

func validateListeners(listeners []Listener) error {
	seen := make(map[string]Status, len(listeners))
	for i, l := range listeners {
		if l == nil {
			return fmt.Errorf("listener[%d] is nil", i)
		}
		id := l.ID()
		if id == "" {
			return fmt.Errorf("listener[%d]: id is required", i)
		}
		st := l.Status()
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate listener id %q", id)
		}
		if err := validateBind(id, st.Bind); err != nil {
			return err
		}
		for _, other := range seen {
			if bindsConflict(st, other) {
				return fmt.Errorf("listener bind conflict: %s and %s (%s %s)", id, other.ID, networkOf(st.Carrier), st.Bind)
			}
		}
		seen[id] = st
	}
	return nil
}

func validateBind(id, bind string) error {
	if bind == "" {
		return fmt.Errorf("listener %s: bind is required", id)
	}
	if _, _, err := net.SplitHostPort(bind); err != nil {
		return fmt.Errorf("listener %s: invalid bind %q", id, bind)
	}
	return nil
}

func networkOf(c domain.Carrier) string {
	switch c {
	case domain.CarrierRADIUSUDP:
		return "udp"
	default:
		return "tcp"
	}
}

func bindsConflict(a, b Status) bool {
	na, ha, pa, wa, ea, ok := parseBind(a)
	if !ok {
		return false
	}
	nb, hb, pb, wb, eb, ok := parseBind(b)
	if !ok {
		return false
	}
	if ea || eb {
		return false
	}
	if na != nb || pa != pb {
		return false
	}
	if wa || wb {
		return true
	}
	ipa := net.ParseIP(ha)
	ipb := net.ParseIP(hb)
	if ipa != nil && ipb != nil {
		return ipa.Equal(ipb)
	}
	return ha == hb
}

func parseBind(st Status) (network, host, port string, wildcard, ephemeral, ok bool) {
	network = networkOf(st.Carrier)
	h, p, err := net.SplitHostPort(st.Bind)
	if err != nil {
		return "", "", "", false, false, false
	}
	if p == "0" {
		return network, h, p, false, true, true
	}
	host = strings.Trim(h, "[]")
	switch host {
	case "", "0.0.0.0", "::", "*":
		wildcard = true
	}
	return network, host, p, wildcard, false, true
}

// Len is the number of registered listeners.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.listeners)
}

// Get returns the listener with id, or nil.
func (r *Registry) Get(id string) Listener {
	if r == nil {
		return nil
	}
	return r.byID[id]
}

// HasProtocol reports whether any registered listener speaks p.
func (r *Registry) HasProtocol(p domain.Protocol) bool {
	if r == nil {
		return false
	}
	for _, l := range r.listeners {
		if l.Protocol() == p {
			return true
		}
	}
	return false
}

// HasReadyAAA reports that a TACACS or RADIUS listener is accepting.
func (r *Registry) HasReadyAAA() bool {
	if r == nil {
		return false
	}
	for _, l := range r.listeners {
		switch l.Protocol() {
		case domain.ProtocolTACACS, domain.ProtocolRADIUS:
			if l.Ready() {
				return true
			}
		}
	}
	return false
}

// Start launches each listener in ID order. errc must have room for Len
// sends; the caller sizes it for extra process sockets (obs, HTTP).
func (r *Registry) Start(ctx context.Context, errc chan<- error) error {
	if r == nil {
		return fmt.Errorf("nil registry")
	}
	if errc == nil {
		return fmt.Errorf("error channel is required")
	}
	if !r.started.CompareAndSwap(false, true) {
		return fmt.Errorf("registry already started")
	}
	for _, l := range r.listeners {
		l := l
		go func() { errc <- l.Start(ctx) }()
	}
	return nil
}

// Ready reports that every required listener is accepting. An empty
// registry is not ready.
func (r *Registry) Ready() bool {
	if r == nil || len(r.listeners) == 0 {
		return false
	}
	for _, l := range r.listeners {
		if l.Status().Required && !l.Ready() {
			return false
		}
	}
	return true
}

// Statuses returns live rows in ID order.
func (r *Registry) Statuses() []Status {
	if r == nil {
		return nil
	}
	out := make([]Status, len(r.listeners))
	for i, l := range r.listeners {
		out[i] = l.Status()
	}
	return out
}

// Drain stops listeners in reverse ID order and waits up to ctx.
func (r *Registry) Drain(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var first error
	for i := len(r.listeners) - 1; i >= 0; i-- {
		if err := r.listeners[i].Drain(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Close releases sockets in reverse ID order. It does not wait for drain.
func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	var first error
	for i := len(r.listeners) - 1; i >= 0; i-- {
		if err := r.listeners[i].Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

var _ StatusProvider = (*Registry)(nil)
