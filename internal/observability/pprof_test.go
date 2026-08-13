package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPprofOffByDefault(t *testing.T) {
	t.Parallel()
	s := New(Options{MetricsEnabled: true, MetricsBind: "127.0.0.1:0"})
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("pprof must be off by default, got %d", rr.Code)
	}
}

func TestPprofNeverOnAdminHandler(t *testing.T) {
	t.Parallel()
	s := New(Options{MetricsEnabled: true, ExposeOnAdmin: true, PprofEnabled: true, MetricsBind: "127.0.0.1:0"})
	h := s.AdminMetricsHandler()
	if h == nil {
		t.Fatal("expected admin metrics handler")
	}
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	// Admin handler is only /metrics; pprof must not be attached.
	if rr.Code == http.StatusOK && len(rr.Body.Bytes()) > 0 && containsPprofIndex(rr.Body.String()) {
		t.Fatal("pprof index served on admin handler")
	}
}

func TestPprofOnDedicatedMuxWhenEnabled(t *testing.T) {
	t.Parallel()
	s := New(Options{PprofEnabled: true})
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("dedicated pprof status=%d", rr.Code)
	}
}

func containsPprofIndex(s string) bool {
	return len(s) > 0 && (contains(s, "Types of profiles available") || contains(s, "allocs") && contains(s, "heap"))
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()))
}
