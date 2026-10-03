package rest

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
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestEventsStreamSurvivesWriteTimeout(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	h.Server.WriteTimeout = 80 * time.Millisecond
	hs := &http.Server{Addr: "127.0.0.1:0", Handler: h.Server.Handler(), WriteTimeout: 80 * time.Millisecond}
	ln, err := net.Listen("tcp", hs.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go hs.Serve(ln) //nolint:errcheck
	t.Cleanup(func() { _ = hs.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("ct=%s", ct)
	}
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("accel")
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

func TestEventsStreamBodiesAndLastEventID(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	first := h.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "start", UserID: "alice", Command: "show"})
	if first.ID == 0 {
		t.Fatal("accept")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream?category=acct", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Last-Event-ID", "0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	var sawStart, sawStop bool
	go func() {
		time.Sleep(20 * time.Millisecond)
		h.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "stop", UserID: "alice"})
		h.Ring.Accept(events.Event{Category: events.CategoryAuthen, Type: "ascii", UserID: "bob"})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !(sawStart && sawStop) {
		if !sc.Scan() {
			if err := sc.Err(); err != nil && !strings.Contains(err.Error(), "canceled") {
				t.Fatal(err)
			}
			break
		}
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev struct {
			Type   string `json:"type"`
			UserID string `json:"user_id"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "start":
			sawStart = true
			if ev.UserID != "alice" {
				t.Fatalf("sensitive user missing: %+v", ev)
			}
		case "stop":
			sawStop = true
		case "ascii":
			t.Fatal("category filter leaked authen")
		}
	}
	if !sawStart || !sawStop {
		t.Fatalf("start=%v stop=%v", sawStart, sawStop)
	}
}

func TestEventsStreamInvalidLastEventID(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", h.Token, nil, map[string]string{"Last-Event-ID": "not-a-cursor"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "invalid_argument" {
		t.Fatalf("code=%q", problem.Code)
	}
}

func TestEventsStreamSlowSubscriberReset(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	h.Server.SSEBuffer = 1
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	tmp := make([]byte, 64)
	n, err := resp.Body.Read(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(tmp[:n], []byte("keepalive")) {
		t.Fatalf("need first frame: %q", tmp[:n])
	}
	for i := 0; i < 8; i++ {
		if h.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "flood"}).ID == 0 {
			t.Fatal("accept")
		}
	}
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	all := append(tmp[:n], rest...)
	if !bytes.Contains(all, []byte("event: reset")) {
		t.Fatalf("expected reset, body=%q", all)
	}
}

func TestEventsStreamRequiresEventsRead(t *testing.T) {
	t.Parallel()
	h := restHarnessScopes(t, []string{"state:read"})
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", h.Token, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
}

func TestEventsStreamRedactsWithoutSensitive(t *testing.T) {
	t.Parallel()
	h := restHarnessScopes(t, []string{"events:read"})
	h.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "start", UserID: "alice", Command: "configure"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if strings.Contains(body, "alice") || strings.Contains(body, "configure") {
		t.Fatalf("leaked sensitive: %s", body)
	}
}

func TestEventsStreamCompleteReplay(t *testing.T) {
	h := restHarness(t)
	ring := events.New(1000, nil)
	defer ring.Close()
	h.Server.Events = ring
	for i := 0; i < 450; i++ {
		ring.Accept(events.Event{Category: events.CategoryAcct, Type: "replay"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Last-Event-ID", "0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	ring.Accept(events.Event{Category: events.CategoryAcct, Type: "live"})
	sc := bufio.NewScanner(resp.Body)
	count := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") {
			count++
			if strings.Contains(line, `"type":"live"`) {
				break
			}
		}
	}
	if count != 451 {
		t.Fatalf("replay plus live count=%d want451", count)
	}
}

func TestEventsStreamRevocation(t *testing.T) {
	h := restHarness(t)
	h.Server.WriteTimeout = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer "+h.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rev := h.Mgr.Revision()
	if _, err := h.Mgr.DeleteToken("lab", state.DeleteOptions{}, &rev); err != nil {
		t.Fatal(err)
	}
	h.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "must-not-leak"})
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("stream did not terminate: %v", err)
	}
	if strings.Contains(string(raw), "must-not-leak") {
		t.Fatalf("revoked stream leaked: %s", raw)
	}
}

func TestEventsStreamSharedAdmission(t *testing.T) {
	h := restHarness(t)
	for i := 0; i < events.MaxSubscribers; i++ {
		_, _, cancel, err := h.Ring.TrySubscribe(1)
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()
	}
	req, _ := http.NewRequest(http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer "+h.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("saturated SSE status%d", resp.StatusCode)
	}
}

func TestEventsStreamCookieRecreation(t *testing.T) {
	h := restHarness(t)
	sess, err := h.Auth.Create(operations.Actor{ID: "lab"}, h.Mgr.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", nil)
	req.AddCookie(auth.SessionCookie(sess))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cookie stream status %d", resp.StatusCode)
	}
	if _, err = h.Mgr.DeleteToken("lab", state.DeleteOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Mgr.CreateToken(state.CreateToken{ID: "lab", Scopes: []string{"events:read", "events:sensitive"}, Material: credentials.NewTokenMaterial([]byte(h.Token))}, nil); err != nil {
		t.Fatal(err)
	}
	h.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "must-not-leak"})
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("recreated cookie stream did not terminate: %v", err)
	}
	if strings.Contains(string(raw), "must-not-leak") {
		t.Fatalf("recreated cookie stream leaked: %s", raw)
	}
}

func TestEventsStreamShutdown(t *testing.T) {
	h := restHarness(t)
	stop := make(chan struct{})
	h.Server.Done = stop
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTP.URL+"/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer "+h.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	close(stop)
	if _, err = io.ReadAll(resp.Body); err != nil {
		t.Fatalf("shutdown stream did not terminate: %v", err)
	}
}

type replayStopWriter struct {
	*httptest.ResponseRecorder
	stop func()
	once sync.Once
}

func (w *replayStopWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	if bytes.Contains(p, []byte(`"type":"replay"`)) {
		w.once.Do(w.stop)
	}
	return n, err
}

func TestEventsReplayStopsDuringWindow(t *testing.T) {
	for _, kind := range []string{"shutdown", "request-cancel"} {
		t.Run(kind, func(t *testing.T) {
			h := restHarness(t)
			ring := events.New(1000, nil)
			defer ring.Close()
			h.Server.Events = ring
			for i := 0; i < 450; i++ {
				ring.Accept(events.Event{Category: events.CategoryAcct, Type: "replay"})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := make(chan struct{})
			h.Server.Done = stop
			signal := cancel
			if kind == "shutdown" {
				signal = func() { close(stop) }
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/api/v1/events/stream", nil)
			req.Header.Set("Authorization", "Bearer "+h.Token)
			req.Header.Set("Last-Event-ID", "0")
			w := &replayStopWriter{ResponseRecorder: httptest.NewRecorder(), stop: signal}
			h.Server.Handler().ServeHTTP(w, req)
			if count := strings.Count(w.Body.String(), `"type":"replay"`); count != 1 {
				t.Fatalf("replay ignored %s: delivered%d bodies", kind, count)
			}
		})
	}
}
