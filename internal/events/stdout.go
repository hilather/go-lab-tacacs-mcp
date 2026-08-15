package events

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxJSONFieldBytes = 512
	// RedactedValue is stored for restricted fields (usernames, commands,
	// Acct-Session-Id) when events:sensitive is not granted.
	RedactedValue    = "<redacted>"
	redactedSentinel = RedactedValue
)

// logLine is the stable stdout JSON object. Level is always "info":
// audit acceptance is independent of process log level.
type logLine struct {
	TS            string `json:"ts"`
	Level         string `json:"level"`
	Event         string `json:"event"`
	Category      string `json:"category"`
	Type          string `json:"type"`
	Result        string `json:"result"`
	ID            uint64 `json:"id"`
	Revision      uint64 `json:"revision,omitempty"`
	Transport     string `json:"transport,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	SessionID     uint32 `json:"session_id,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	AcctSessionID string `json:"acct_session_id,omitempty"`
	TaskID        string `json:"task_id,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	Command       string `json:"command,omitempty"`
	Schema        int    `json:"schema_version"`
}

// WriteJSON writes one sanitized JSON line. It never emits control characters
// or secret-bearing fields. UserID, command text, and AcctSessionID are
// redacted when redact is true.
func WriteJSON(w io.Writer, e Event, redact bool) error {
	if w == nil {
		return nil
	}
	ts := e.Time
	if ts.IsZero() {
		ts = time.Time{}
	}
	name := e.Category
	if e.Type != "" {
		if name != "" {
			name += "."
		}
		name += e.Type
	}
	line := logLine{
		TS:        ts.UTC().Format(time.RFC3339Nano),
		Level:     "info",
		Event:     sanitize(name),
		Category:  sanitize(e.Category),
		Type:      sanitize(e.Type),
		Result:    sanitize(e.Result),
		ID:        e.ID,
		Revision:  uint64(e.Revision),
		Transport: sanitize(e.Transport),
		ClientID:  sanitize(e.ClientID),
		SessionID: e.SessionID,
		Protocol:  sanitize(e.Protocol),
		TaskID:    sanitize(e.TaskID),
		Schema:    e.SchemaVersion,
	}
	if line.Schema == 0 {
		line.Schema = SchemaVersion
	}
	if redact {
		if e.UserID != "" {
			line.UserID = redactedSentinel
		}
		if e.Command != "" {
			line.Command = redactedSentinel
		}
		if e.AcctSessionID != "" {
			line.AcctSessionID = redactedSentinel
		}
	} else {
		line.UserID = sanitize(e.UserID)
		line.Command = sanitize(e.Command)
		line.AcctSessionID = sanitize(e.AcctSessionID)
	}
	raw, err := json.Marshal(line)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.Grow(len(raw) + 1)
	buf.Write(raw)
	buf.WriteByte('\n')
	_, err = w.Write(buf.Bytes())
	return err
}

func sanitize(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > maxJSONFieldBytes {
		s = trimToBytes(s, maxJSONFieldBytes)
	}
	if strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x20 || r == 0x7f || r == utf8.RuneError
	}) {
		out := make([]rune, 0, len(s))
		for _, r := range s {
			if r < 0x20 || r == 0x7f || r == utf8.RuneError {
				out = append(out, ' ')
			} else {
				out = append(out, r)
			}
		}
		return string(out)
	}
	return s
}

func trimToBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}
