package tls

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

type lookup uint8

const (
	lookupMiss lookup = iota
	lookupHit
	lookupPending
	lookupSaturated
	lookupPurged
)

type slotKey struct {
	endpointID string
	role       domain.ListenerRole
	src        string
	listenerID string
	code       codec.Code
	id         uint8
}

type fingerprint struct {
	auth   [codec.AuthenticatorSize]byte
	digest [32]byte
}

type cacheEntry struct {
	pending  bool
	fp       fingerprint
	response []byte
	expires  time.Time
	bytes    int
}

type cache struct {
	mu         sync.Mutex
	entries    map[slotKey]*cacheEntry
	maxEntries int
	maxBytes   int
	usedBytes  int
	ttl        time.Duration
	now        func() time.Time
}

func newCache(entries, bytes int, ttl time.Duration, now func() time.Time) *cache {
	if entries <= 0 {
		entries = 1
	}
	if bytes <= 0 {
		bytes = 4096
	}
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &cache{
		entries:    make(map[slotKey]*cacheEntry, entries),
		maxEntries: entries,
		maxBytes:   bytes,
		ttl:        ttl,
		now:        now,
	}
}

func fingerprintOf(declared []byte) fingerprint {
	var fp fingerprint
	if len(declared) >= codec.HeaderSize {
		copy(fp.auth[:], declared[4:codec.HeaderSize])
	}
	fp.digest = sha256.Sum256(declared)
	return fp
}

func sameFP(a, b fingerprint) bool {
	return a.auth == b.auth && a.digest == b.digest
}

func (c *cache) Begin(key slotKey, fp fingerprint) (lookup, []byte) {
	if c == nil {
		return lookupMiss, nil
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)

	purged := false
	if e, ok := c.entries[key]; ok {
		if sameFP(e.fp, fp) {
			if e.pending {
				return lookupPending, nil
			}
			out := append([]byte(nil), e.response...)
			return lookupHit, out
		}
		c.removeLocked(key)
		purged = true
	}
	if len(c.entries) >= c.maxEntries {
		return lookupSaturated, nil
	}
	c.entries[key] = &cacheEntry{
		pending: true,
		fp:      fp,
		expires: now.Add(c.ttl),
	}
	if purged {
		return lookupPurged, nil
	}
	return lookupMiss, nil
}

func (c *cache) Complete(key slotKey, fp fingerprint, response []byte) {
	if c == nil {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !e.pending || !sameFP(e.fp, fp) {
		return
	}
	n := len(response)
	if c.usedBytes+n > c.maxBytes {
		c.removeLocked(key)
		return
	}
	e.pending = false
	e.response = append([]byte(nil), response...)
	e.bytes = n
	e.expires = now.Add(c.ttl)
	c.usedBytes += n
}

func (c *cache) Abandon(key slotKey, fp fingerprint) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !sameFP(e.fp, fp) {
		return
	}
	c.removeLocked(key)
}

func (c *cache) expireLocked(now time.Time) {
	for k, e := range c.entries {
		if !e.expires.After(now) {
			c.removeLocked(k)
		}
	}
}

func (c *cache) removeLocked(key slotKey) {
	e, ok := c.entries[key]
	if !ok {
		return
	}
	c.usedBytes -= e.bytes
	if c.usedBytes < 0 {
		c.usedBytes = 0
	}
	delete(c.entries, key)
}
