package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestListenAcknowledgedAndURIOnly(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp := startListen(t, ctx, h, map[string]any{
		"resourceSubscriptions": []string{resourceEventsRecent},
		"toolsListChanged":      true,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("ct=%s", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("accel")
	}

	ack := readSSEData(t, resp.Body)
	if ack["method"] != "notifications/subscriptions/acknowledged" {
		t.Fatalf("ack=%v", ack)
	}
	params, _ := ack["params"].(map[string]any)
	notes, _ := params["notifications"].(map[string]any)
	if notes["toolsListChanged"] != true {
		t.Fatalf("notes=%v", notes)
	}
	subs, _ := notes["resourceSubscriptions"].([]any)
	if len(subs) != 1 || subs[0] != resourceEventsRecent {
		t.Fatalf("subs=%v", subs)
	}

	h.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "start", UserID: "alice", Command: "show running-config"})
	note := readSSEData(t, resp.Body)
	if note["method"] != "notifications/resources/updated" {
		t.Fatalf("note=%v", note)
	}
	np, _ := note["params"].(map[string]any)
	if np["uri"] != resourceEventsRecent {
		t.Fatalf("uri=%v", np)
	}
	raw, _ := json.Marshal(note)
	if bytes.Contains(raw, []byte("alice")) || bytes.Contains(raw, []byte("show running-config")) || bytes.Contains(raw, []byte("acct")) {
		t.Fatalf("event body leaked on listen: %s", raw)
	}
}

func TestListenSurvivesWriteTimeout(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	h.Opts.WriteTimeout = 80 * time.Millisecond
	hs := &http.Server{Addr: "127.0.0.1:0", Handler: Handler(h.Opts), WriteTimeout: 80 * time.Millisecond}
	ln, err := net.Listen("tcp", hs.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go hs.Serve(ln) //nolint:errcheck
	t.Cleanup(func() { _ = hs.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := listenRequest(t, ctx, "http://"+ln.Addr().String()+"/mcp", h.Token, map[string]any{
		"resourceSubscriptions": []string{resourceEventsRecent},
	})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 64)
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if bytes.Count(buf, []byte("keepalive")) >= 2 {
			return
		}
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if err == io.EOF {
			t.Fatalf("stream closed early (write timeout?) body=%q", buf)
		}
	}
	if !bytes.Contains(buf, []byte("keepalive")) {
		t.Fatalf("body=%q", buf)
	}
}

func TestListenOmitsUnauthorizedResources(t *testing.T) {
	t.Parallel()
	h := mcpHarnessScopes(t, []string{"state:read"}, config.MCP{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp := startListen(t, ctx, h, map[string]any{
		"resourceSubscriptions": []string{resourceEventsRecent, "taclab://status"},
	})
	defer resp.Body.Close()
	ack := readSSEData(t, resp.Body)
	params, _ := ack["params"].(map[string]any)
	notes, _ := params["notifications"].(map[string]any)
	subs, _ := notes["resourceSubscriptions"].([]any)
	if len(subs) != 1 || subs[0] != "taclab://status" {
		t.Fatalf("subs=%v notes=%v", subs, notes)
	}
}

func TestListenCompleteOnShutdown(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	stop := make(chan struct{})
	h.Opts.Done = stop
	hs := &http.Server{Addr: "127.0.0.1:0", Handler: Handler(h.Opts)}
	hs.RegisterOnShutdown(func() { close(stop) })
	ln, err := net.Listen("tcp", hs.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go hs.Serve(ln) //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := listenRequest(t, ctx, "http://"+ln.Addr().String()+"/mcp", h.Token, map[string]any{
		"resourceSubscriptions": []string{resourceEventsRecent},
	})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	_ = readSSEData(t, resp.Body)

	shutCtx, shutCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutCancel()
	if err := hs.Shutdown(shutCtx); err != nil {
		t.Fatal(err)
	}
	final := readSSEData(t, resp.Body)
	res, _ := final["result"].(map[string]any)
	if res["resultType"] != resultTypeComplete {
		t.Fatalf("expected complete on shutdown, got %v", final)
	}
}

func TestListenListChangedOnOverlayRevision(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	h.Opts.WriteTimeout = 20 * time.Millisecond
	h.Opts.IdleTimeout = 20 * time.Millisecond
	ts := httptest.NewServer(Handler(h.Opts))
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := listenRequest(t, ctx, ts.URL+"/mcp", h.Token, map[string]any{
		"toolsListChanged":     true,
		"resourcesListChanged": true,
	})
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	ack := readSSEData(t, resp.Body)
	notes, _ := ack["params"].(map[string]any)["notifications"].(map[string]any)
	if notes["toolsListChanged"] != true || notes["resourcesListChanged"] != true {
		t.Fatalf("ack notes=%v", notes)
	}

	before := h.Mgr.Revision()
	enabled := false
	if _, err := h.Mgr.CreateUser(state.CreateUser{ID: "listen-rev", Enabled: &enabled}, &before); err != nil {
		t.Fatal(err)
	}

	var acc []byte
	tmp := make([]byte, 512)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			acc = append(acc, tmp[:n]...)
		}
		got := string(acc)
		if strings.Contains(got, "notifications/tools/list_changed") && strings.Contains(got, "notifications/resources/list_changed") {
			return
		}
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if err == io.EOF {
			break
		}
	}
	t.Fatalf("missing list_changed after overlay mutation body=%q", acc)
}

func TestListenCompleteOnRingClose(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp := startListen(t, ctx, h, map[string]any{
		"resourceSubscriptions": []string{resourceEventsRecent},
	})
	defer resp.Body.Close()
	_ = readSSEData(t, resp.Body)
	h.Ring.Close()
	final := readSSEData(t, resp.Body)
	if final["result"] == nil {
		t.Fatalf("expected complete result, got %v", final)
	}
	res, _ := final["result"].(map[string]any)
	if res["resultType"] != resultTypeComplete {
		t.Fatalf("result=%v", res)
	}
}

func startListen(t testing.TB, ctx context.Context, h *harness, notifications map[string]any) *http.Response {
	t.Helper()
	req := listenRequest(t, ctx, h.HTTP.URL+"/mcp", h.Token, notifications)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func listenRequest(t testing.TB, ctx context.Context, url, token string, notifications map[string]any) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "subscriptions/listen",
		"params": map[string]any{
			"notifications": notifications,
			"_meta":         defaultMeta(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerProtocolVersion, protocolVersion)
	req.Header.Set(headerMethod, "subscriptions/listen")
	req.Header.Set("Accept", "application/json, text/event-stream")
	return req
}

func readSSEData(t testing.TB, r io.Reader) map[string]any {
	t.Helper()
	br := bufio.NewReader(r)
	var data []byte
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read sse: %v", err)
		}
		s := strings.TrimRight(string(line), "\r\n")
		if strings.HasPrefix(s, ":") {
			continue
		}
		if strings.HasPrefix(s, "data: ") {
			data = []byte(strings.TrimPrefix(s, "data: "))
			continue
		}
		if s == "" && len(data) > 0 {
			var out map[string]any
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("sse json=%s err=%v", data, err)
			}
			return out
		}
	}
}
