package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAPIUnauthenticated(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp, err := http.Get(h.HTTP.URL + "/api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != openAPIVersion {
		t.Fatalf("openapi=%v", doc["openapi"])
	}
	paths, _ := doc["paths"].(map[string]any)
	if _, ok := paths["/api/v1/status"]; !ok {
		t.Fatal("missing status")
	}
	if _, ok := paths["/api/v1/users"]; !ok {
		t.Fatal("missing users")
	}
	if _, ok := paths["/api/v1/config/effective"]; !ok {
		t.Fatal("missing config/effective")
	}
	if _, ok := paths["/api/v1/authentication/test"]; !ok {
		t.Fatal("missing authentication.test")
	}
	if _, ok := paths["/api/v1/radius/access:test"]; !ok {
		t.Fatal("missing radius.access.test")
	}
	if _, ok := paths["/api/v1/radius/policy:evaluate"]; !ok {
		t.Fatal("missing radius.policy.evaluate")
	}
	if _, ok := paths["/api/v1/radius/attributes"]; !ok {
		t.Fatal("missing radius.attributes.list")
	}
	if _, ok := paths["/api/v1/session"]; !ok {
		t.Fatal("missing session")
	}
	if _, ok := paths["/api/v1/events/stream"]; !ok {
		t.Fatal("missing stream")
	}
}

func TestWriteGeneratedMatchesLive(t *testing.T) {
	t.Parallel()
	root := findRepoRoot(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(root, "api", "operations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "api", "operations.yaml"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/hilather/go-lab-tacacs-mcp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteGenerated(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, OpenAPIPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"operationId": "system.status.get"`) {
		t.Fatalf("openapi missing status: %s", got[:min(200, len(got))])
	}
	ts, err := os.ReadFile(filepath.Join(dir, TSTypesPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"export interface Status", "export interface Session", "export interface CreatedToken", "export interface EventView", "export interface ProblemDetails"} {
		if !strings.Contains(string(ts), want) {
			t.Fatalf("ts missing %s", want)
		}
	}
}

func TestOpenAPIStable(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	a, err := marshalStable(BuildOpenAPI(h.Server.Registry))
	if err != nil {
		t.Fatal(err)
	}
	b, err := marshalStable(BuildOpenAPI(h.Server.Registry))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("openapi not deterministic")
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func TestOpenAPIJSONContentType(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp, err := http.Get(h.HTTP.URL + "/api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("ct=%s", resp.Header.Get("Content-Type"))
	}
}
