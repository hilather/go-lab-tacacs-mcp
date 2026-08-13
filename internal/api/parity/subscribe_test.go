package parity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
)

// events.subscribe is PARITY_DIFFERENT_BINDING. Compare domain events, not
// SSE vs JSON-RPC wire identity.
func TestEventsSubscribeDomainEquivalence(t *testing.T) {
	t.Parallel()
	_, restW, mcpW := isolatedTrio(t, allScopes)

	restCtx, restCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer restCancel()
	restReq, err := http.NewRequestWithContext(restCtx, http.MethodGet, restW.HTTP.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	restReq.Header.Set("Authorization", "Bearer "+restW.Token)
	restResp, err := http.DefaultClient.Do(restReq)
	if err != nil {
		t.Fatal(err)
	}
	defer restResp.Body.Close()
	if restResp.StatusCode != http.StatusOK {
		t.Fatalf("rest stream status=%d", restResp.StatusCode)
	}

	mcpCtx, mcpCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer mcpCancel()
	mcpReq := listenRequest(t, mcpCtx, mcpW.HTTP.URL+"/mcp", mcpW.Token, map[string]any{
		"resourceSubscriptions": []string{"taclab://events/recent"},
	})
	mcpResp, err := http.DefaultClient.Do(mcpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer mcpResp.Body.Close()
	if mcpResp.StatusCode != http.StatusOK {
		t.Fatalf("mcp listen status=%d", mcpResp.StatusCode)
	}
	restSSE := newSSEReader(restResp.Body)
	mcpSSE := newSSEReader(mcpResp.Body)
	ack := mcpSSE.nextJSON(t)
	if ack["method"] != "notifications/subscriptions/acknowledged" {
		t.Fatalf("ack=%v", ack)
	}

	ev := events.Event{
		Category: events.CategoryAPI,
		Type:     "api.user.created",
		Result:   "ok",
		UserID:   "alice",
		Command:  "show running-config",
	}
	restW.Ring.Accept(ev)
	mcpW.Ring.Accept(ev)

	restBody := restSSE.nextRESTEvent(t)
	if restBody["type"] != ev.Type || restBody["category"] != ev.Category || restBody["result"] != ev.Result {
		t.Fatalf("rest body=%v", restBody)
	}
	if restBody["user_id"] != "alice" || restBody["command"] != "show running-config" {
		t.Fatalf("sensitive fields missing on REST: %v", restBody)
	}

	note := mcpSSE.nextJSON(t)
	if note["method"] != "notifications/resources/updated" {
		t.Fatalf("mcp note=%v", note)
	}
	params, _ := note["params"].(map[string]any)
	if params["uri"] != "taclab://events/recent" {
		t.Fatalf("mcp uri=%v", params)
	}
	rawNote, _ := json.Marshal(note)
	if bytes.Contains(rawNote, []byte("alice")) || bytes.Contains(rawNote, []byte("show running-config")) || bytes.Contains(rawNote, []byte("api.user.created")) {
		t.Fatalf("event body leaked on MCP listen: %s", rawNote)
	}

	listed := invoke(t, mcpW, operations.IDEventsList, operations.ListEventsRequest{Limit: 20}, callOpts{})
	items, _ := asMap(listed.Data)["items"].([]any)
	if len(items) == 0 {
		t.Fatal("mcp events.list empty after notify")
	}
	last := asMap(items[len(items)-1])
	if last["type"] != restBody["type"] || last["category"] != restBody["category"] || last["result"] != restBody["result"] {
		t.Fatalf("domain event rest=%v mcp.list=%v", restBody, last)
	}
	if last["user_id"] != restBody["user_id"] || last["command"] != restBody["command"] {
		t.Fatalf("redaction mismatch rest=%v mcp=%v", restBody, last)
	}
}

func TestEventsSubscribeRedactsWithoutSensitiveScope(t *testing.T) {
	t.Parallel()
	_, restW, mcpW := isolatedTrio(t, []string{"events:read"})
	restW.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "start", UserID: "alice", Command: "show"})
	mcpW.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "start", UserID: "alice", Command: "show"})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, restW.HTTP.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+restW.Token)
	req.Header.Set("Last-Event-ID", "0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := newSSEReader(resp.Body).nextRESTEvent(t)
	if body["user_id"] != nil && body["user_id"] != "" {
		t.Fatalf("REST leaked user without events:sensitive: %v", body)
	}
	if body["command"] != nil && body["command"] != "" {
		t.Fatalf("REST leaked command without events:sensitive: %v", body)
	}

	listed := invoke(t, mcpW, operations.IDEventsList, operations.ListEventsRequest{Limit: 10}, callOpts{})
	items, _ := asMap(listed.Data)["items"].([]any)
	if len(items) == 0 {
		t.Fatal("mcp list empty")
	}
	got := asMap(items[0])
	if got["user_id"] != nil && got["user_id"] != "" {
		t.Fatalf("MCP leaked user without events:sensitive: %v", got)
	}
	if got["type"] != body["type"] || got["category"] != body["category"] {
		t.Fatalf("domain mismatch rest=%v mcp=%v", body, got)
	}
}

func TestEventsSubscribeDenyShapes(t *testing.T) {
	t.Parallel()
	_, restW, mcpW := isolatedTrio(t, []string{"state:read"})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	restReq, err := http.NewRequestWithContext(ctx, http.MethodGet, restW.HTTP.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	restReq.Header.Set("Authorization", "Bearer "+restW.Token)
	restResp, err := http.DefaultClient.Do(restReq)
	if err != nil {
		t.Fatal(err)
	}
	defer restResp.Body.Close()
	if restResp.StatusCode != http.StatusForbidden {
		t.Fatalf("REST subscribe without events:read status=%d", restResp.StatusCode)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(restResp.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != string(domain.CodePermissionDenied) {
		t.Fatalf("REST subscribe code=%q", problem.Code)
	}

	mcpReq := listenRequest(t, ctx, mcpW.HTTP.URL+"/mcp", mcpW.Token, map[string]any{
		"resourceSubscriptions": []string{"taclab://events/recent", "taclab://status"},
	})
	mcpResp, err := http.DefaultClient.Do(mcpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer mcpResp.Body.Close()
	if mcpResp.StatusCode != http.StatusOK {
		t.Fatalf("MCP listen status=%d", mcpResp.StatusCode)
	}
	ack := newSSEReader(mcpResp.Body).nextJSON(t)
	if ack["method"] != "notifications/subscriptions/acknowledged" {
		t.Fatalf("ack=%v", ack)
	}
	params, _ := ack["params"].(map[string]any)
	notes, _ := params["notifications"].(map[string]any)
	subs, _ := notes["resourceSubscriptions"].([]any)
	for _, s := range subs {
		if s == "taclab://events/recent" {
			t.Fatalf("MCP listen accepted unauthorized events URI: %v", notes)
		}
	}
	if len(subs) != 1 || subs[0] != "taclab://status" {
		t.Fatalf("expected only taclab://status, notes=%v", notes)
	}

	listed := invoke(t, mcpW, operations.IDEventsList, operations.ListEventsRequest{Limit: 5}, callOpts{})
	if listed.Code != string(domain.CodePermissionDenied) {
		t.Fatalf("events.list without events:read code=%q body=%s", listed.Code, listed.Raw)
	}
}

type sseReader struct {
	sc *bufio.Scanner
}

func newSSEReader(r io.Reader) *sseReader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	return &sseReader{sc: sc}
}

func (s *sseReader) nextJSON(t testing.TB) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.sc.Scan() {
		line := s.sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &out); err != nil {
			continue
		}
		return out
	}
	if err := s.sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("timed out waiting for SSE JSON")
	return nil
}

func (s *sseReader) nextRESTEvent(t testing.TB) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ev := s.nextJSON(t)
		if ev["type"] != nil || ev["category"] != nil {
			return ev
		}
	}
	t.Fatal("timed out waiting for REST event body")
	return nil
}

func listenRequest(t testing.TB, ctx context.Context, url, token string, notifications map[string]any) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "subscriptions/listen",
		"params": map[string]any{
			"notifications": notifications,
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    mcpProtocolVersion,
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
				"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "taclab-parity", "version": "test"},
			},
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
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	req.Header.Set("Mcp-Method", "subscriptions/listen")
	return req
}
