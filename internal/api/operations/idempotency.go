package operations

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const replayReservation = 64 << 10

type replayEntry struct {
	fingerprint [32]byte
	done        chan struct{}
	expires     time.Time
	revision    domain.Revision
	body        []byte
	code        domain.Code
}

type replayStore struct {
	mu       sync.Mutex
	secret   [32]byte
	entries  map[[32]byte]*replayEntry
	now      func() time.Time
	ttl      time.Duration
	capacity int
}

func newReplayStore() *replayStore {
	s := &replayStore{entries: make(map[[32]byte]*replayEntry), now: time.Now, ttl: 10 * time.Minute, capacity: (8 << 20) / replayReservation}
	if _, err := rand.Read(s.secret[:]); err != nil {
		panic("idempotency entropy unavailable")
	}
	return s
}

func supportsReplay(id string) bool {
	switch id {
	case IDUsersCreate, IDGroupsCreate, IDClientsCreate, IDRuntimeReset, IDConfigReload:
		return true
	}
	return false
}

func (s *replayStore) digest(v any) ([32]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return [32]byte{}, domain.NewError(domain.CodeInvalidArgument, "idempotency input cannot be encoded")
	}
	mac := hmac.New(sha256.New, s.secret[:])
	mac.Write(b)
	clear(b)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out, nil
}

func (r *Registry) invokeReplay(ctx context.Context, id string, snap *state.Snapshot, in Input, got registered) (Result, error) {
	if !supportsReplay(id) {
		return Result{}, domain.NewError(domain.CodeInvalidArgument, "operation does not support idempotency keys")
	}
	if len(in.IdempotencyKey) > 256 {
		return Result{}, domain.NewError(domain.CodeInvalidArgument, "idempotency key exceeds 256 bytes")
	}
	scopes := cloneStrings(in.Actor.Scopes)
	sort.Strings(scopes)
	s := r.replay
	key, err := s.digest(struct {
		Actor      string
		Generation domain.Revision
		Scopes     []string
		Key        []byte
	}{in.Actor.ID, snap.TokenGeneration(in.Actor.ID), scopes, []byte(in.IdempotencyKey)})
	if err != nil {
		return Result{}, err
	}
	fingerprint, err := s.digest(struct {
		Operation string
		Revision  *domain.Revision
		Request   any
		Hidden    map[string]any
	}{id, in.ExpectedRevision, in.Request, requestSemantics(in.Request)})
	if err != nil {
		return Result{}, err
	}
	s.mu.Lock()
	now := s.now()
	for k, e := range s.entries {
		if !e.expires.IsZero() && !now.Before(e.expires) {
			delete(s.entries, k)
		}
	}
	if e, ok := s.entries[key]; ok {
		if e.fingerprint != fingerprint {
			s.mu.Unlock()
			return Result{}, domain.NewError(domain.CodeConflict, "idempotency key reused with different input")
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-e.done:
		}
		if e.code != "" {
			return Result{}, domain.NewError(e.code, "idempotency result unavailable; use a new key after checking state")
		}
		v := reflect.New(got.resp)
		if err := json.Unmarshal(e.body, v.Interface()); err != nil {
			return Result{}, domain.NewError(domain.CodeInternal, "idempotency replay decode failed")
		}
		return Result{Revision: e.revision, Data: v.Elem().Interface()}, nil
	}
	if len(s.entries) >= s.capacity {
		s.mu.Unlock()
		return Result{}, domain.NewError(domain.CodeUnavailable, "idempotency store is full")
	}
	e := &replayEntry{fingerprint: fingerprint, done: make(chan struct{})}
	s.entries[key] = e
	s.mu.Unlock()
	completed := false
	defer func() {
		if !completed {
			s.mu.Lock()
			e.code = domain.CodeUnavailable
			e.expires = s.now().Add(s.ttl)
			close(e.done)
			s.mu.Unlock()
		}
	}()
	result, err := r.invokeHandler(ctx, id, snap, in, got)
	body, encodeErr := json.Marshal(result.Data)
	s.mu.Lock()
	e.revision = result.Revision
	e.code = domain.CodeUnavailable
	if failure, ok := domain.AsError(err); ok {
		e.code = failure.Code
	}
	if err == nil && encodeErr == nil && len(body) <= replayReservation {
		e.body = body
		e.code = ""
	}
	e.expires = s.now().Add(s.ttl)
	close(e.done)
	completed = true
	s.mu.Unlock()
	return result, err
}

// Secret ref and optional policy flags are intentionally omitted from wire JSON.
// Include them in the fingerprint so omission and explicit clearing never alias.
func requestSemantics(request any) map[string]any {
	out := map[string]any{}
	var walk func(reflect.Value, string)
	walk = func(v reflect.Value, path string) {
		if v.Kind() == reflect.Pointer {
			if !v.IsNil() {
				walk(v.Elem(), path)
			}
			return
		}
		if v.Type() == reflect.TypeOf(OptionalSecret{}) {
			s := v.Interface().(OptionalSecret)
			out[path] = []bool{s.Present, s.Clear}
			return
		}
		if v.Type() == reflect.TypeOf(OptionalPolicyID{}) {
			s := v.Interface().(OptionalPolicyID)
			out[path] = []bool{s.Present, s.Clear}
			return
		}
		switch v.Kind() {
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					walk(v.Field(i), path+"/"+v.Type().Field(i).Name)
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), path+"/"+strconv.Itoa(i))
			}
		}
	}
	walk(reflect.ValueOf(request), "")
	return out
}
