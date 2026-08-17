package peap

import "sync"

// Registry holds live PEAP tunnels keyed by a consume-on-use handle.
type Registry struct {
	mu    sync.Mutex
	items map[string]*Tunnel
}

// NewRegistry builds an empty tunnel table.
func NewRegistry() *Registry {
	return &Registry{items: make(map[string]*Tunnel)}
}

// Put stores t under id. A nil registry is a no-op.
func (r *Registry) Put(id string, t *Tunnel) {
	if r == nil || id == "" || t == nil {
		return
	}
	r.mu.Lock()
	r.items[id] = t
	r.mu.Unlock()
}

// Get returns the tunnel for id, or nil.
func (r *Registry) Get(id string) *Tunnel {
	if r == nil || id == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.items[id]
}

// Delete removes id without closing the tunnel.
func (r *Registry) Delete(id string) {
	if r == nil || id == "" {
		return
	}
	r.mu.Lock()
	delete(r.items, id)
	r.mu.Unlock()
}

// Reset closes and drops every tunnel.
func (r *Registry) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.items {
		t.Close()
		delete(r.items, id)
	}
}
