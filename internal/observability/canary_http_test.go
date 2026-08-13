package observability_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type httpTestServer struct {
	URL   string
	close func()
}

func (s *httpTestServer) Close() { s.close() }

func startHTTPTest(t *testing.T, h http.Handler) *httpTestServer {
	t.Helper()
	ts := httptest.NewServer(h)
	return &httpTestServer{URL: ts.URL, close: ts.Close}
}

func do(t *testing.T, method, url, token string, body []byte) []byte {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}
