package radius

import (
	"net/netip"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const evaluatorName = "radius_access"

const (
	sourceClientPrefix = "client_policy:"
	sourceFallback     = "fallback"
)

// Request is RADIUS access-policy input. Groups are already the effective
// ordered set. Attributes are typed; secret values must not be supplied.
type Request struct {
	UserID     string
	ClientID   string
	EndpointID string
	Method     domain.AuthMethod
	Groups     []string
	Attributes TypedSet
}

// Result is the first-match access decision plus a deterministic trace.
type Result struct {
	Effect          domain.Effect
	ReplyAttributes TypedSet
	Trace           Trace
}

// Trace is a secret-free explanation. Attribute values never appear.
type Trace struct {
	Evaluator   string       `json:"evaluator"`
	UserID      string       `json:"user_id"`
	ClientID    string       `json:"client_id"`
	EndpointID  string       `json:"endpoint_id"`
	Method      string       `json:"method"`
	Groups      []string     `json:"groups"`
	Steps       []TraceStep  `json:"steps"`
	Winner      *TraceWinner `json:"winner"`
	Effect      string       `json:"effect"`
	DefaultDeny string       `json:"default_deny,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// TraceStep is one considered rule.
type TraceStep struct {
	Source  string `json:"source"`
	RuleID  string `json:"rule_id"`
	Matched bool   `json:"matched"`
	Reason  string `json:"reason"`
}

// TraceWinner names the first matching rule.
type TraceWinner struct {
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
	Effect string `json:"effect"`
}

// AttrKey is a vendor/code identity. Vendor 0 is IETF.
type AttrKey struct {
	Vendor uint32
	Code   uint8
	Name   string
}

// Equal reports whether vendor and code match. Name is diagnostic only.
func (k AttrKey) Equal(o AttrKey) bool {
	return k.Vendor == o.Vendor && k.Code == o.Code
}

// Typed is one application-safe attribute. Secret kinds are rejected at compile.
type Typed struct {
	Key  AttrKey
	Kind ValueKind
	Text string
	Uint uint32
	Addr netip.Addr
	Raw  []byte
}

// TypedSet is an ordered, duplicate-preserving list of typed attributes.
type TypedSet []Typed

// First returns the first instance of key.
func (s TypedSet) First(key AttrKey) (Typed, bool) {
	for _, a := range s {
		if a.Key.Equal(key) {
			return a, true
		}
	}
	return Typed{}, false
}

// Present reports whether any instance of key exists.
func (s TypedSet) Present(key AttrKey) bool {
	_, ok := s.First(key)
	return ok
}

func (s TypedSet) clone() TypedSet {
	if s == nil {
		return TypedSet{}
	}
	out := make(TypedSet, len(s))
	for i, a := range s {
		out[i] = a
		if a.Raw != nil {
			out[i].Raw = append([]byte(nil), a.Raw...)
		}
	}
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
