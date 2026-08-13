package rest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSPAFallbackDoesNotCaptureAPI(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	h.Server.Assets = fstest.MapFS{
		"index.html":                   {Data: []byte("<!doctype html><title>TacLab</title>")},
		"assets/index-0123456789ab.js": {Data: []byte("ok")},
	}
	ts := httptest.NewServer(h.Server.Handler())
	t.Cleanup(ts.Close)

	dash, err := http.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer dash.Body.Close()
	body, _ := io.ReadAll(dash.Body)
	if dash.StatusCode != http.StatusOK || !strings.Contains(string(body), "TacLab") {
		t.Fatalf("SPA GET /dashboard status=%d body=%s", dash.StatusCode, body)
	}
	if got := dash.Header.Get("Cache-Control"); !strings.Contains(got, "no-cache") {
		t.Fatalf("index cache=%q", got)
	}

	asset, err := http.Get(ts.URL + "/assets/index-0123456789ab.js")
	if err != nil {
		t.Fatal(err)
	}
	defer asset.Body.Close()
	if asset.StatusCode != http.StatusOK {
		t.Fatalf("asset status=%d", asset.StatusCode)
	}
	if got := asset.Header.Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("hashed cache=%q", got)
	}

	users := doAuth(t, http.MethodGet, ts.URL+"/api/v1/users", h.Token, nil, nil)
	defer users.Body.Close()
	if users.StatusCode != http.StatusNotFound {
		t.Fatalf("users status=%d", users.StatusCode)
	}

	live, err := http.Get(ts.URL + "/health/live")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Body.Close()
	if live.StatusCode != http.StatusOK {
		t.Fatalf("live status=%d", live.StatusCode)
	}
	raw, _ := io.ReadAll(live.Body)
	if strings.Contains(string(raw), "<!doctype") {
		t.Fatal("health served HTML")
	}
}

func TestDefaultEmbedServesStubIndex(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp, err := http.Get(h.HTTP.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "TacLab") {
		t.Fatalf("body=%s", body)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-cache") {
		t.Fatalf("cache=%q", got)
	}
}
