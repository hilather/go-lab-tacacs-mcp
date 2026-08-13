package main

import "time"

// Report is the machine-readable lab-test output.
type Report struct {
	OK         bool             `json:"ok"`
	Phase      string           `json:"phase"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt time.Time        `json:"finished_at"`
	HTTP       string           `json:"http"`
	Legacy     string           `json:"legacy"`
	TLS        string           `json:"tls"`
	Scenarios  []ScenarioResult `json:"scenarios"`
	SourceIP   string           `json:"source_ip,omitempty"`
}

// ScenarioResult is one LAB-* row.
type ScenarioResult struct {
	ID         string `json:"id"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type scenario struct {
	ID string
	Fn func() error
}

type harness struct {
	HTTP       string
	Legacy     string
	TLS        string
	Token      string
	Secret     []byte
	PKI        string
	Passwords  map[string]string
	WriteTO    time.Duration
	Phase      string
	ServerName string
	Started    time.Time
	canaries   []string
	sourceNote string
}

func (h *harness) pw(id string) string {
	if h.Passwords == nil {
		return ""
	}
	return h.Passwords[id]
}
