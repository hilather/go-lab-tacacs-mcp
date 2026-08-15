package udp

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

// Lookup is the retransmission-cache outcome for one datagram.
type Lookup uint8

const (
	// LookupMiss: caller owns a pending slot and must Complete or Abandon.
	LookupMiss Lookup = iota
	// LookupHit: Response is the exact cached reply bytes.
	LookupHit
	// LookupPending: an in-flight exact duplicate; silent discard.
	LookupPending
	// LookupSaturated: no room for a new pending slot; drop_overload.
	LookupSaturated
	// LookupPurged: same slot, different Request Authenticator; caller owns
	// a new pending entry (treat as miss after recording a purge).
	LookupPurged
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

// Cache is the exact-response retransmission cache. It stores no secrets
// and no decrypted attributes — only coordination state and reply bytes.
type Cache struct {
	mu         sync.Mutex
	entries    map[slotKey]*cacheEntry
	maxEntries int
	maxBytes   int
	usedBytes  int
	ttl        time.Duration
	now        func() time.Time
}

func newCache(entries, bytes int, ttl time.Duration, now func() time.Time) *Cache {
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
	return &Cache{
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

// Begin looks up or reserves a slot. A different Request Authenticator on
// the same Access (or accounting) slot purges the old entry first.
func (c *Cache) Begin(key slotKey, fp fingerprint) (Lookup, []byte) {
	if c == nil {
		return LookupMiss, nil
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)

	purged := false
	if e, ok := c.entries[key]; ok {
		if sameFP(e.fp, fp) {
			if e.pending {
				return LookupPending, nil
			}
			out := append([]byte(nil), e.response...)
			return LookupHit, out
		}
		c.removeLocked(key)
		purged = true
	}
	if len(c.entries) >= c.maxEntries {
		return LookupSaturated, nil
	}
	c.entries[key] = &cacheEntry{
		pending: true,
		fp:      fp,
		expires: now.Add(c.ttl),
	}
	if purged {
		return LookupPurged, nil
	}
	return LookupMiss, nil
}

// Complete stores exact reply bytes for a pending slot.
func (c *Cache) Complete(key slotKey, fp fingerprint, response []byte) {
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

// Abandon drops a pending slot so a discard cannot leave a stuck entry.
func (c *Cache) Abandon(key slotKey, fp fingerprint) {
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

func (c *Cache) expireLocked(now time.Time) {
	for k, e := range c.entries {
		if !e.expires.After(now) {
			c.removeLocked(k)
		}
	}
}

func (c *Cache) removeLocked(key slotKey) {
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

func (c *Cache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
