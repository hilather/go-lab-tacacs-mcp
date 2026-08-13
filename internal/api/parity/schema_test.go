package parity

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/rest"
	"github.com/hilather/go-lab-tacacs-mcp/tools/registry"
)

func TestSchemaEquivalence(t *testing.T) {
	t.Parallel()
	root, err := operations.FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := operations.NewFromRepo(root, operations.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	openapi := rest.BuildOpenAPI(reg)
	components, _ := openapi["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	if len(schemas) == 0 {
		t.Fatal("OpenAPI schemas missing")
	}

	w := newWorld(t, "mcp", allScopes, "mcp")
	listed := mcpRPC(t, w.HTTP, w.Token, "tools/list", nil)
	tools, _ := listed.result["tools"].([]any)
	byName := map[string]map[string]any{}
	for _, raw := range tools {
		m, _ := raw.(map[string]any)
		name, _ := m["name"].(string)
		byName[name] = m
	}

	tsRaw, err := os.ReadFile(filepath.Join(root, rest.TSTypesPath))
	if err != nil {
		t.Fatal(err)
	}
	tsTypes := tsInterfaceNames(string(tsRaw))

	for _, op := range reg.List() {
		if op.Parity != registry.ParityRequired {
			continue
		}
		if !op.Implemented {
			t.Errorf("%s not implemented", op.ID)
			continue
		}
		goReq := goJSONFields(op.Request)
		goResp := goJSONFields(op.Response)
		oaReq := schemaPropNames(schemas[op.RequestType])
		oaResp := schemaPropNames(schemas[op.ResponseType])
		if op.RequestType != "" && schemas[op.RequestType] != nil && !sameStrings(goReq, oaReq) {
			t.Errorf("%s request fields go=%v openapi=%v", op.ID, goReq, oaReq)
		}
		if op.ResponseType != "" && schemas[op.ResponseType] != nil && !sameStrings(goResp, oaResp) {
			t.Errorf("%s response fields go=%v openapi=%v", op.ID, goResp, oaResp)
		}
		if op.MCP.Kind != "tool" || op.MCP.Name == "" {
			continue
		}
		tool := byName[op.MCP.Name]
		if tool == nil {
			t.Errorf("%s MCP tool %s missing from tools/list", op.ID, op.MCP.Name)
			continue
		}
		inProps := schemaPropNames(tool["inputSchema"])
		outProps := schemaPropNames(tool["outputSchema"])
		inProps = dropStrings(inProps, "expected_revision", "idempotency_key")
		if !sameStrings(goReq, inProps) {
			t.Errorf("%s MCP input fields go=%v mcp=%v", op.ID, goReq, inProps)
		}
		if !sameStrings(goResp, outProps) {
			t.Errorf("%s MCP output fields go=%v mcp=%v", op.ID, goResp, outProps)
		}
		if op.Mutating {
			allIn := schemaPropNames(tool["inputSchema"])
			if !contains(allIn, "expected_revision") || !contains(allIn, "idempotency_key") {
				t.Errorf("%s mutating MCP input missing expected_revision/idempotency_key: %v", op.ID, allIn)
			}
		}
		if _, ok := tsTypes[op.RequestType]; op.RequestType != "" && op.Request != nil && op.Request.Kind() == reflect.Struct && op.Request.NumField() > 0 && !ok {
			t.Errorf("%s request type %s missing from generated TypeScript", op.ID, op.RequestType)
		}
		if _, ok := tsTypes[op.ResponseType]; op.ResponseType != "" && !ok {
			t.Errorf("%s response type %s missing from generated TypeScript", op.ID, op.ResponseType)
		}
	}
}

func schemaPropNames(v any) []string {
	m, _ := v.(map[string]any)
	if m == nil {
		return nil
	}
	props, _ := m["properties"].(map[string]any)
	if props == nil {
		return nil
	}
	out := make([]string, 0, len(props))
	for k := range props {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dropStrings(in []string, drop ...string) []string {
	skip := map[string]struct{}{}
	for _, d := range drop {
		skip[d] = struct{}{}
	}
	var out []string
	for _, s := range in {
		if _, ok := skip[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

func tsInterfaceNames(src string) map[string]struct{} {
	re := regexp.MustCompile(`(?m)^export interface (\w+)`)
	out := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

func TestTSTypesCoverParityResponses(t *testing.T) {
	t.Parallel()
	root, err := operations.FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, rest.TSTypesPath))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, name := range []string{"Status", "BuildInfo", "User", "Group", "Client", "PolicyTrace", "EventList", "CreatedToken"} {
		if !strings.Contains(text, "export interface "+name+" ") && !strings.Contains(text, "export interface "+name+"{") {
			t.Errorf("generated TS missing %s", name)
		}
	}
}
