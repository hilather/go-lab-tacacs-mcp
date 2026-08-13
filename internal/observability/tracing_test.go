package observability

import (
	"context"
	"strings"
	"testing"
)

func TestTracerOffByDefault(t *testing.T) {
	t.Parallel()
	tr := NewTracer(false)
	ctx, sp := tr.Start(context.Background(), "conn", Attr{Key: "transport", Value: "legacy"})
	sp.SetAttr(Attr{Key: "packet_body", Value: "secret-bytes"})
	sp.End()
	if len(tr.FinishedSpans()) != 0 {
		t.Fatal("disabled tracer must not retain spans")
	}
	if SpanFromContext(ctx).Name() != "" {
		t.Fatal("disabled span should be no-op")
	}
}

func TestTracerRedactsForbiddenAttributes(t *testing.T) {
	t.Parallel()
	tr := NewTracer(true)
	_, sp := tr.Start(context.Background(), "operation",
		Attr{Key: "operation_id", Value: "users.list"},
		Attr{Key: "password", Value: "unit-test-trace-canary-zz01"},
		Attr{Key: "packet_body", Value: "raw"},
		Attr{Key: "unknown_freeform", Value: "nope"},
	)
	sp.End()
	spans := tr.FinishedSpans()
	if len(spans) != 1 {
		t.Fatalf("spans=%d", len(spans))
	}
	for _, a := range spans[0].Attrs {
		if a.Key == "password" || a.Key == "packet_body" || a.Key == "unknown_freeform" {
			t.Fatalf("forbidden attr retained: %+v", a)
		}
		if strings.Contains(a.Value, "unit-test-trace-canary-zz01") {
			t.Fatalf("canary in attr: %+v", a)
		}
	}
	if len(spans[0].Attrs) != 1 || spans[0].Attrs[0].Key != "operation_id" {
		t.Fatalf("attrs=%+v", spans[0].Attrs)
	}
}
