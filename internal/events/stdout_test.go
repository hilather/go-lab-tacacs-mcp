package events

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestWriteJSONStableFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	ev := Event{
		SchemaVersion: SchemaVersion,
		ID:            7,
		Time:          time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC),
		Category:      CategoryAcct,
		Type:          "start",
		Result:        "success",
		ClientID:      "lab-switches",
		SessionID:     9,
		UserID:        "lab-admin",
		Command:       "configure terminal",
		TaskID:        "task-1",
	}
	if err := WriteJSON(&buf, ev, true); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}
	if got["level"] != "info" || got["event"] != "acct.start" || got["id"] != float64(7) {
		t.Fatalf("line=%s", line)
	}
	if got["user_id"] != redactedSentinel || got["command"] != redactedSentinel {
		t.Fatalf("redaction: %s", line)
	}
	if strings.Contains(line, "lab-admin") || strings.Contains(line, "configure") {
		t.Fatalf("leaked user/command: %s", line)
	}
}

func TestWriteJSONSanitizesControlAndOversize(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	long := strings.Repeat("a", maxJSONFieldBytes+50)
	ev := Event{
		ID:       1,
		Time:     time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC),
		Category: "acct\n",
		Type:     "start\x00evil",
		Result:   "success",
		ClientID: long,
	}
	if err := WriteJSON(&buf, ev, false); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	if strings.Contains(raw, "\n\n") || strings.Contains(raw, "\x00") {
		t.Fatalf("control leaked: %q", raw)
	}
	if strings.Count(raw, "\n") != 1 {
		t.Fatalf("want one JSON line, got %q", raw)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &got); err != nil {
		t.Fatal(err)
	}
	if cid, _ := got["client_id"].(string); len(cid) > maxJSONFieldBytes {
		t.Fatalf("oversized field %d", len(cid))
	}
}

func TestWriteJSONRedactsAcctSessionID(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	ev := Event{
		SchemaVersion: SchemaVersion,
		ID:            3,
		Time:          time.Date(2026, 8, 14, 16, 0, 0, 0, time.UTC),
		Category:      CategoryAcct,
		Type:          "stop",
		Result:        "success",
		Protocol:      "radius",
		AcctSessionID: "nas-sess-should-redact",
		UserID:        "lab-admin",
	}
	if err := WriteJSON(&buf, ev, true); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(buf.String())
	if strings.Contains(line, "nas-sess-should-redact") || strings.Contains(line, "lab-admin") {
		t.Fatalf("leaked: %s", line)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}
	if got["acct_session_id"] != redactedSentinel || got["user_id"] != redactedSentinel {
		t.Fatalf("redaction: %s", line)
	}
	if got["protocol"] != "radius" {
		t.Fatalf("protocol=%v", got["protocol"])
	}
	if _, ok := got["session_id"]; ok {
		t.Fatalf("uint32 session_id present: %s", line)
	}
}

func TestWriteJSONOmitsRADIUSFieldsForTACACS(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	ev := Event{
		SchemaVersion: SchemaVersion,
		ID:            1,
		Time:          time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC),
		Category:      CategoryAcct,
		Type:          "start",
		Result:        "success",
		SessionID:     9,
	}
	if err := WriteJSON(&buf, ev, true); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["acct_session_id"]; ok {
		t.Fatalf("TACACS stdout leaked acct_session_id: %s", line)
	}
	if _, ok := got["protocol"]; ok {
		t.Fatalf("TACACS stdout leaked protocol: %s", line)
	}
	if got["session_id"] != float64(9) {
		t.Fatalf("TACACS session_id=%v", got["session_id"])
	}
}

func TestWriteJSONSecretCanary(t *testing.T) {
	t.Parallel()
	canaries := []string{
		"unit-test-login-canary-acct-aa11",
		"unit-test-shared-secret-canary-bb22",
		"lab-bootstrap-token-32-bytes!!!",
	}
	var buf bytes.Buffer
	ev := Event{
		ID:       1,
		Time:     time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC),
		Category: CategoryAcct,
		Type:     "start",
		Result:   "success",
		ClientID: "lab-switches",
		UserID:   "lab-admin",
	}
	if err := WriteJSON(&buf, ev, true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, c := range canaries {
		if strings.Contains(out, c) {
			t.Fatalf("canary %q in stdout: %s", c, out)
		}
	}
}

func TestStdoutAsyncDoesNotBlockAccept(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	w := writerFunc(func([]byte) (int, error) {
		<-block
		return 0, nil
	})
	r := NewWithOptions(Options{Capacity: 4, Stdout: w, StdoutBuffer: 1})
	t.Cleanup(func() {
		close(block)
		r.Close()
	})
	// First send fills the buffer (loop may or may not have taken it).
	r.Accept(Event{Category: CategoryAcct, Type: "start"})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 8; i++ {
			if r.Accept(Event{Category: CategoryAcct, Type: "start"}).ID == 0 {
				t.Error("accept rejected")
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accept blocked on stdout")
	}
	if r.StdoutDropped() == 0 {
		t.Fatal("expected stdout drops under backpressure")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
