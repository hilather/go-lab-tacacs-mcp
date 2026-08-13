package observability

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMetricsListener(t *testing.T) {
	t.Parallel()
	s := New(Options{MetricsEnabled: true, MetricsBind: "127.0.0.1:0", MetricsPath: "/metrics"})
	s.Rec.SetRevision(7)
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ctx) }()
	addr := s.Addr()
	if addr == nil {
		t.Fatal("no addr")
	}
	resp, err := http.Get("http://" + addr.String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !strings.Contains(string(body), MetricStateRevision) {
		t.Fatalf("missing revision: %s", body)
	}
	shut, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := s.Shutdown(shut); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("serve hung")
	}
}

func TestAdminMetricsOmitsPprof(t *testing.T) {
	t.Parallel()
	s := New(Options{MetricsEnabled: true, ExposeOnAdmin: true, PprofEnabled: true})
	h := s.AdminMetricsHandler()
	if h == nil {
		t.Fatal("nil admin handler")
	}
}
