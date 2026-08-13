package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkStatus(b *testing.B) {
	h := restHarness(b)
	req, err := http.NewRequest(http.MethodGet, h.HTTP.URL+"/api/v1/status", nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	client := h.HTTP.Client()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("status=%d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func BenchmarkMiddlewareOverhead(b *testing.B) {
	s := &Server{Ready: func() bool { return true }}
	ts := httptest.NewServer(s.Handler())
	b.Cleanup(ts.Close)
	client := ts.Client()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(ts.URL + "/health/live")
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}
