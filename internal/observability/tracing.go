package observability

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Attribute keys that must never appear on a span.
var forbiddenTraceKeys = map[string]struct{}{
	"packet_body":   {},
	"body":          {},
	"password":      {},
	"secret":        {},
	"shared_secret": {},
	"challenge":     {},
	"token":         {},
	"cookie":        {},
	"private_key":   {},
	"verifier":      {},
	"raw":           {},
}

// allowedTraceKeys is the closed set of redacted attributes.
var allowedTraceKeys = map[string]struct{}{
	"listener":     {},
	"transport":    {},
	"operation_id": {},
	"result_class": {},
	"error_code":   {},
	"revision":     {},
	"request_id":   {},
	"client_id":    {},
	"session_id":   {},
	"authen_type":  {},
}

type spanCtxKey struct{}

// Attr is one redacted span attribute.
type Attr struct {
	Key   string
	Value string
}

// Span is a tracing span. Implementations must not retain packet bodies.
type Span interface {
	End()
	SetAttr(Attr)
	RecordError(error)
	Name() string
	Attrs() []Attr
}

// Tracer is a process-local tracing hook. It is off unless Enabled is true.
type Tracer struct {
	Enabled bool

	mu    sync.Mutex
	spans []recordedSpan
}

type recordedSpan struct {
	Name  string
	Attrs []Attr
	Err   string
	Start time.Time
	End   time.Time
}

type liveSpan struct {
	t     *Tracer
	name  string
	attrs []Attr
	err   string
	start time.Time
	once  sync.Once
}

type noopSpan struct{}

func (noopSpan) End()              {}
func (noopSpan) SetAttr(Attr)      {}
func (noopSpan) RecordError(error) {}
func (noopSpan) Name() string      { return "" }
func (noopSpan) Attrs() []Attr     { return nil }

// NewTracer returns a tracer. Enabled defaults to false.
func NewTracer(enabled bool) *Tracer {
	return &Tracer{Enabled: enabled}
}

// Start begins a span. When disabled it returns a no-op.
func (t *Tracer) Start(ctx context.Context, name string, attrs ...Attr) (context.Context, Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	if t == nil || !t.Enabled {
		return ctx, noopSpan{}
	}
	sp := &liveSpan{t: t, name: name, start: time.Now()}
	for _, a := range attrs {
		sp.SetAttr(a)
	}
	return context.WithValue(ctx, spanCtxKey{}, sp), sp
}

// SpanFromContext returns the current span or a no-op.
func SpanFromContext(ctx context.Context) Span {
	if ctx == nil {
		return noopSpan{}
	}
	if s, ok := ctx.Value(spanCtxKey{}).(Span); ok && s != nil {
		return s
	}
	return noopSpan{}
}

func (s *liveSpan) End() {
	s.once.Do(func() {
		if s.t == nil {
			return
		}
		s.t.mu.Lock()
		s.t.spans = append(s.t.spans, recordedSpan{
			Name:  s.name,
			Attrs: append([]Attr(nil), s.attrs...),
			Err:   s.err,
			Start: s.start,
			End:   time.Now(),
		})
		// Bound retained spans so an enabled tracer cannot grow without limit.
		if len(s.t.spans) > 256 {
			s.t.spans = s.t.spans[len(s.t.spans)-256:]
		}
		s.t.mu.Unlock()
	})
}

func (s *liveSpan) SetAttr(a Attr) {
	if a.Key == "" {
		return
	}
	if _, bad := forbiddenTraceKeys[a.Key]; bad {
		return
	}
	if _, ok := allowedTraceKeys[a.Key]; !ok {
		return
	}
	if len(a.Value) > 128 {
		a.Value = a.Value[:128]
	}
	s.attrs = append(s.attrs, a)
}

func (s *liveSpan) RecordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	if len(msg) > 128 {
		msg = msg[:128]
	}
	s.err = msg
	s.SetAttr(Attr{Key: "error_code", Value: "internal"})
}

func (s *liveSpan) Name() string  { return s.name }
func (s *liveSpan) Attrs() []Attr { return append([]Attr(nil), s.attrs...) }

// SpanDump is a test helper that serializes finished spans without secrets.
func (t *Tracer) SpanDump() string {
	var b strings.Builder
	for _, s := range t.FinishedSpans() {
		b.WriteString(s.Name)
		b.WriteByte(' ')
		b.WriteString(s.Err)
		for _, a := range s.Attrs {
			b.WriteByte(' ')
			b.WriteString(a.Key)
			b.WriteByte('=')
			b.WriteString(a.Value)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// FinishedSpans is a test helper. Production scrapes do not use this.
func (t *Tracer) FinishedSpans() []recordedSpan {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]recordedSpan, len(t.spans))
	copy(out, t.spans)
	return out
}
