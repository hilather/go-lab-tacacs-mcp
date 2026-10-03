package peap

import (
	"sync"
	"time"
)

// Each admitted tunnel reserves its bounded input, output, fragment and
// queued-flight buffers against the registry byte budget.
const tunnelReservationBytes = 4 * MaxTLSFlightBytes

type registryEntry struct {
	tunnel  *Tunnel
	expires time.Time
	timer   *time.Timer
}

// Registry holds a bounded, expiring table of live PEAP tunnels.
type Registry struct {
	mu         sync.Mutex
	items      map[string]registryEntry
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
}

func NewRegistry() *Registry { return NewRegistryWithLimits(4096, 1<<20, 30*time.Second, nil) }

// NewRegistryWithLimits reuses the Challenge capacity/TTL configuration
// for a separate PEAP reservation budget, not shared byte accounting.
// Buffer reservations can make the tunnel cap smaller than the State cap.
func NewRegistryWithLimits(entries, bytes int, ttl time.Duration, now func() time.Time) *Registry {
	if entries <= 0 {
		entries = 4096
	}
	if bytes <= 0 {
		bytes = 1 << 20
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &Registry{items: make(map[string]registryEntry), maxEntries: min(entries, bytes/tunnelReservationBytes), ttl: ttl, now: now}
}

// Put admits a tunnel without evicting a live conversation. The caller
// retains ownership on failure and must close the unadmitted tunnel.
func (r *Registry) Put(id string, t *Tunnel) bool {
	if r == nil || id == "" || t == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.expireLocked(now)
	if _, exists := r.items[id]; exists || len(r.items) >= r.maxEntries {
		return false
	}
	timer := time.AfterFunc(r.ttl, func() { r.mu.Lock(); defer r.mu.Unlock(); r.expireLocked(r.now()) })
	r.items[id] = registryEntry{tunnel: t, expires: now.Add(r.ttl), timer: timer}
	return true
}

// Get returns a live tunnel and extends its continuation deadline.
func (r *Registry) Get(id string) *Tunnel {
	if r == nil || id == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.expireLocked(now)
	e, ok := r.items[id]
	if !ok {
		return nil
	}
	e.expires = now.Add(r.ttl)
	e.timer.Reset(r.ttl)
	r.items[id] = e
	return e.tunnel
}

// Delete closes and removes the tunnel.
func (r *Registry) Delete(id string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.items[id]; ok {
		e.timer.Stop()
		e.tunnel.Close()
		delete(r.items, id)
	}
}

func (r *Registry) expireLocked(now time.Time) {
	for id, e := range r.items {
		if !e.expires.After(now) {
			e.timer.Stop()
			e.tunnel.Close()
			delete(r.items, id)
		}
	}
}

func (r *Registry) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, e := range r.items {
		e.timer.Stop()
		e.tunnel.Close()
		delete(r.items, id)
	}
}
