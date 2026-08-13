package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Evidence is the sanitized Cisco-lab report. Secrets must not appear.
type Evidence struct {
	Status            string            `json:"status"`
	Reason            string            `json:"reason"`
	StartedAt         time.Time         `json:"started_at"`
	FinishedAt        time.Time         `json:"finished_at"`
	CiscoPass         bool              `json:"cisco_pass"`
	DeviceFamilyClaim bool              `json:"device_family_completeness"`
	ConformanceClaim  string            `json:"conformance_claim"`
	WouldPull         bool              `json:"would_pull"`
	Login             string            `json:"login,omitempty"`
	Enable            string            `json:"enable,omitempty"`
	Authorization     string            `json:"authorization,omitempty"`
	Accounting        string            `json:"accounting,omitempty"`
	CapabilityNotes   []string          `json:"capability_notes,omitempty"`
	IOLImageRef       string            `json:"iol_image_ref,omitempty"`
	Extra             map[string]string `json:"extra,omitempty"`
}

func decisionEvidence(d Decision) Evidence {
	return Evidence{
		Status:            d.Status,
		Reason:            d.Reason,
		StartedAt:         time.Now().UTC(),
		FinishedAt:        time.Now().UTC(),
		CiscoPass:         false,
		DeviceFamilyClaim: false,
		ConformanceClaim:  "none",
		WouldPull:         false,
		IOLImageRef:       d.IOLImage,
	}
}

var secretLine = regexp.MustCompile(`(?i)(key|password|secret|token|bearer|authorization:)\s+\S+`)

// SanitizeEvidenceText strips secret-shaped tokens from operator-facing logs.
func SanitizeEvidenceText(s string, extraSecrets ...string) string {
	out := secretLine.ReplaceAllString(s, "${1} <redacted>")
	for _, sec := range extraSecrets {
		if sec == "" {
			continue
		}
		out = strings.ReplaceAll(out, sec, "<redacted>")
	}
	return out
}

func writeEvidence(path string, ev Evidence) error {
	if path == "" {
		return nil
	}
	ev.Reason = SanitizeEvidenceText(ev.Reason)
	ev.Login = SanitizeEvidenceText(ev.Login)
	ev.Enable = SanitizeEvidenceText(ev.Enable)
	ev.Authorization = SanitizeEvidenceText(ev.Authorization)
	ev.Accounting = SanitizeEvidenceText(ev.Accounting)
	for i, n := range ev.CapabilityNotes {
		ev.CapabilityNotes[i] = SanitizeEvidenceText(n)
	}
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func parsePasswordsFile(body string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
