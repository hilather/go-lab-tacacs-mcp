package parity

import (
	"os"
	"path/filepath"
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
	tsProps := tsInterfaceProps(string(tsRaw))

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
		if len(goReq) > 0 && schemas[op.RequestType] == nil {
			t.Errorf("%s request type %s missing from OpenAPI", op.ID, op.RequestType)
		}
		if len(goResp) > 0 && schemas[op.ResponseType] == nil {
			t.Errorf("%s response type %s missing from OpenAPI", op.ID, op.ResponseType)
		}
		if schemas[op.RequestType] != nil && !sameStrings(goReq, schemaPropNames(schemas[op.RequestType])) {
			t.Errorf("%s request fields go=%v openapi=%v", op.ID, goReq, schemaPropNames(schemas[op.RequestType]))
		}
		if schemas[op.ResponseType] != nil && !sameStrings(goResp, schemaPropNames(schemas[op.ResponseType])) {
			t.Errorf("%s response fields go=%v openapi=%v", op.ID, goResp, schemaPropNames(schemas[op.ResponseType]))
		}
		if wo := goWriteOnlyFields(op.Request); len(wo) > 0 && schemas[op.RequestType] != nil {
			if got := schemaWriteOnlyNames(schemas[op.RequestType]); !sameStrings(wo, got) {
				t.Errorf("%s writeOnly go=%v openapi=%v", op.ID, wo, got)
			}
		}
		if len(goReq) > 0 {
			if ts, ok := tsProps[op.RequestType]; !ok {
				t.Errorf("%s request type %s missing from generated TypeScript", op.ID, op.RequestType)
			} else if !sameStrings(goReq, ts) {
				t.Errorf("%s request TS fields go=%v ts=%v", op.ID, goReq, ts)
			}
		}
		if len(goResp) > 0 {
			if ts, ok := tsProps[op.ResponseType]; !ok {
				t.Errorf("%s response type %s missing from generated TypeScript", op.ID, op.ResponseType)
			} else if !sameStrings(goResp, ts) {
				t.Errorf("%s response TS fields go=%v ts=%v", op.ID, goResp, ts)
			}
		}
		if op.MCP.Kind != "tool" || op.MCP.Name == "" {
			continue
		}
		tool := byName[op.MCP.Name]
		if tool == nil {
			t.Errorf("%s MCP tool %s missing from tools/list", op.ID, op.MCP.Name)
			continue
		}
		inProps := dropStrings(schemaPropNames(tool["inputSchema"]), "expected_revision", "idempotency_key")
		outProps := schemaPropNames(tool["outputSchema"])
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

func schemaWriteOnlyNames(v any) []string {
	m, _ := v.(map[string]any)
	if m == nil {
		return nil
	}
	props, _ := m["properties"].(map[string]any)
	var out []string
	for k, raw := range props {
		pm, _ := raw.(map[string]any)
		if wo, _ := pm["writeOnly"].(bool); wo {
			out = append(out, k)
		}
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

func contains(have []string, want string) bool {
	for _, s := range have {
		if s == want {
			return true
		}
	}
	return false
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

func tsInterfaceProps(src string) map[string][]string {
	re := regexp.MustCompile(`export interface (\w+) \{`)
	fieldRe := regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\??:`)
	out := map[string][]string{}
	for _, loc := range re.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		body, ok := tsBraceBody(src, loc[1]-1)
		if !ok {
			continue
		}
		var fields []string
		for _, f := range fieldRe.FindAllStringSubmatch(body, -1) {
			fields = append(fields, f[1])
		}
		sort.Strings(fields)
		out[name] = fields
	}
	return out
}

func tsBraceBody(src string, open int) (string, bool) {
	if open < 0 || open >= len(src) || src[open] != '{' {
		return "", false
	}
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : i], true
			}
		}
	}
	return "", false
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
