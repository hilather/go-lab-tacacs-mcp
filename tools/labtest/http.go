package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

func (h *harness) restJSON(method, path string, body any, hdr map[string]string) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.HTTP+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if err := h.rejectCanary(b); err != nil {
		return resp.StatusCode, b, err
	}
	return resp.StatusCode, b, nil
}

func (h *harness) mcpCall(name string, args any) (int, []byte, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": args,
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
				"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "taclab-labtest", "version": "1"},
			},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, h.HTTP+"/mcp", bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", name)
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if err := h.rejectCanary(out); err != nil {
		return resp.StatusCode, out, err
	}
	return resp.StatusCode, out, nil
}

func (h *harness) rejectCanary(b []byte) error {
	for _, c := range h.canaries {
		if c == "" {
			continue
		}
		if bytes.Contains(b, []byte(c)) {
			return fmt.Errorf("secret canary leaked in HTTP body")
		}
	}
	return nil
}

func mustContain(raw []byte, needle string) error {
	if !bytes.Contains(raw, []byte(needle)) {
		snip := string(raw)
		if len(snip) > 240 {
			snip = snip[:240]
		}
		return fmt.Errorf("missing %q in %s", needle, snip)
	}
	return nil
}

func statusOK(code int, raw []byte) error {
	if code < 200 || code >= 300 {
		return fmt.Errorf("http %d: %s", code, strings.TrimSpace(string(raw)))
	}
	return nil
}
