package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	conformanceIDRe = regexp.MustCompile(`T(?:89|98)-[A-Z]+-\d+`)
	operationIDRe   = regexp.MustCompile(`^[a-z]+(?:\.[a-z][a-z0-9_]*)+$`)
	firstColOpRe    = regexp.MustCompile("(?m)^\\|\\s*`([a-z]+(?:\\.[a-z][a-z0-9_]*)+)`\\s*\\|")
	httpMethods     = map[string]struct{}{
		"GET": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {},
	}
	mcpKinds = map[string]struct{}{
		"tool": {}, "resource": {}, "listen": {}, "protocol": {},
	}
)

// Issue is one registry validation failure.
type Issue struct {
	File    string
	ID      string
	Message string
}

func (i Issue) String() string {
	if i.ID == "" {
		return fmt.Sprintf("%s: %s", i.File, i.Message)
	}
	return fmt.Sprintf("%s: %s: %s", i.File, i.ID, i.Message)
}

// Report is the collected result of validating the checked-in registries.
type Report struct {
	Operations *OperationRegistry
	RFC8907    *ConformanceRegistry
	RFC9887    *ConformanceRegistry
	Issues     []Issue
}

// Valid reports whether the report contains no issues.
func (r *Report) Valid() bool {
	return len(r.Issues) == 0
}

func (r *Report) add(file, id, format string, args ...any) {
	r.Issues = append(r.Issues, Issue{File: file, ID: id, Message: fmt.Sprintf(format, args...)})
}

// ValidateRoot loads the checked-in registries and contract docs and
// checks uniqueness, required fields, bindings, and contract coverage.
func ValidateRoot(root string) (*Report, error) {
	rep := &Report{}
	ops, err := LoadOperations(filepath.Join(root, OperationsPath))
	if err != nil {
		return nil, err
	}
	r89, err := LoadConformance(filepath.Join(root, RFC8907Path))
	if err != nil {
		return nil, err
	}
	r98, err := LoadConformance(filepath.Join(root, RFC9887Path))
	if err != nil {
		return nil, err
	}
	rep.Operations = ops
	rep.RFC8907 = r89
	rep.RFC9887 = r98

	validateOperations(rep, OperationsPath, ops)
	validateConformance(rep, RFC8907Path, "8907", r89)
	validateConformance(rep, RFC9887Path, "9887", r98)
	validateConformanceIDUniqueness(rep, r89, r98)

	parityDoc, err := os.ReadFile(filepath.Join(root, ParityDocPath))
	if err != nil {
		return nil, err
	}
	confDoc, err := os.ReadFile(filepath.Join(root, ConformanceDocPath))
	if err != nil {
		return nil, err
	}
	checkOperationContractCoverage(rep, ExtractOperationIDs(parityDoc), ops)
	checkConformanceContractCoverage(rep, ExtractConformanceIDs(confDoc), r89, r98)
	return rep, nil
}

// ExtractConformanceIDs returns unique T89/T98 IDs in document order.
func ExtractConformanceIDs(markdown []byte) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, id := range conformanceIDRe.FindAllString(string(markdown), -1) {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// ExtractOperationIDs returns first-column operation IDs from API_PARITY tables.
func ExtractOperationIDs(markdown []byte) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range firstColOpRe.FindAllStringSubmatch(string(markdown), -1) {
		id := m[1]
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func validateOperations(rep *Report, file string, doc *OperationRegistry) {
	if doc.SchemaVersion != 1 {
		rep.add(file, "", "schema_version must be 1, got %d", doc.SchemaVersion)
	}
	if len(doc.Operations) == 0 {
		rep.add(file, "", "operations table is empty")
	}
	ids := map[string]int{}
	routes := map[string]string{}
	toolNames := map[string]string{}
	for i, op := range doc.Operations {
		if op.ID == "" {
			rep.add(file, fmt.Sprintf("index-%d", i), "missing id")
			continue
		}
		if !operationIDRe.MatchString(op.ID) {
			rep.add(file, op.ID, "invalid operation id")
		}
		if prev, ok := ids[op.ID]; ok {
			rep.add(file, op.ID, "duplicate operation id (first at index %d)", prev)
		} else {
			ids[op.ID] = i
		}
		if _, ok := validDispositions[op.Parity]; !ok {
			rep.add(file, op.ID, "invalid or missing parity disposition %q", op.Parity)
		}
		if _, ok := validIdempotent[op.Idempotent]; !ok {
			rep.add(file, op.ID, "invalid idempotent value %q", op.Idempotent)
		}
		if op.Description == "" {
			rep.add(file, op.ID, "missing description")
		}
		if op.RequestType == "" {
			rep.add(file, op.ID, "missing request_type")
		}
		if op.ResponseType == "" {
			rep.add(file, op.ID, "missing response_type")
		}
		if op.Status == "" {
			rep.add(file, op.ID, "missing status")
		} else if _, ok := validConformanceStatuses[op.Status]; !ok {
			rep.add(file, op.ID, "invalid status %q", op.Status)
		}
		needScope := op.Parity == ParityRequired || op.Parity == ParityDifferentBinding
		if needScope && len(op.Scopes) == 0 {
			rep.add(file, op.ID, "parity disposition %s requires at least one scope", op.Parity)
		}
		for _, scope := range op.Scopes {
			if _, ok := knownScopes[scope]; !ok {
				rep.add(file, op.ID, "unknown scope %q", scope)
			}
		}
		needREST, needMCP := requiredBindings(op.Parity)
		if needREST && op.REST.Empty() {
			rep.add(file, op.ID, "missing REST binding required by %s", op.Parity)
		}
		if needMCP && op.MCP.Empty() {
			rep.add(file, op.ID, "missing MCP binding required by %s", op.Parity)
		}
		if op.Parity == RESTOnlyProtocol && !op.MCP.Empty() {
			rep.add(file, op.ID, "REST_ONLY_PROTOCOL must not declare an MCP binding")
		}
		if op.Parity == MCPOnlyProtocol && !op.REST.Empty() {
			rep.add(file, op.ID, "MCP_ONLY_PROTOCOL must not declare a REST binding")
		}
		if op.Parity == ExemptByADR && strings.TrimSpace(op.ADR) == "" {
			rep.add(file, op.ID, "EXEMPT_BY_ADR requires adr")
		}
		if !op.REST.Empty() {
			if _, ok := httpMethods[op.REST.Method]; !ok {
				rep.add(file, op.ID, "invalid REST method %q", op.REST.Method)
			}
			if op.REST.Path == "" || !strings.HasPrefix(op.REST.Path, "/") {
				rep.add(file, op.ID, "REST path %q must be an absolute path", op.REST.Path)
			}
			key := op.REST.Method + " " + op.REST.Path
			if prev, ok := routes[key]; ok {
				rep.add(file, op.ID, "duplicate REST route %s (also %s)", key, prev)
			} else {
				routes[key] = op.ID
			}
		}
		if !op.MCP.Empty() {
			if _, ok := mcpKinds[op.MCP.Kind]; !ok {
				rep.add(file, op.ID, "invalid MCP kind %q", op.MCP.Kind)
			}
			if op.MCP.Name == "" && op.MCP.Resource == "" {
				rep.add(file, op.ID, "MCP binding requires name or resource")
			}
			if op.MCP.Kind == "tool" {
				if op.MCP.Name == "" {
					rep.add(file, op.ID, "MCP tool binding requires name")
				} else if !strings.HasPrefix(op.MCP.Name, "taclab.") {
					rep.add(file, op.ID, "MCP tool name %q must start with taclab.", op.MCP.Name)
				} else if prev, ok := toolNames[op.MCP.Name]; ok {
					rep.add(file, op.ID, "duplicate MCP tool name %s (also %s)", op.MCP.Name, prev)
				} else {
					toolNames[op.MCP.Name] = op.ID
				}
			}
			if op.MCP.Kind == "listen" {
				if op.MCP.Resource == "" {
					rep.add(file, op.ID, "listen binding requires a resource URI")
				}
				if op.MCP.PullOperation == "" {
					rep.add(file, op.ID, "listen binding requires pull_operation (no event firehose)")
				}
			}
		}
	}
	for _, op := range doc.Operations {
		if op.MCP.PullOperation == "" {
			continue
		}
		if _, ok := ids[op.MCP.PullOperation]; !ok {
			rep.add(file, op.ID, "pull_operation %q is not a registered operation", op.MCP.PullOperation)
		}
	}
}

func requiredBindings(parity string) (rest, mcp bool) {
	switch parity {
	case ParityRequired, ParityDifferentBinding:
		return true, true
	case RESTOnlyProtocol:
		return true, false
	case MCPOnlyProtocol:
		return false, true
	default:
		return false, false
	}
}

func validateConformance(rep *Report, file, wantRFC string, doc *ConformanceRegistry) {
	if doc.SchemaVersion != 1 {
		rep.add(file, "", "schema_version must be 1, got %d", doc.SchemaVersion)
	}
	if doc.RFC != wantRFC {
		rep.add(file, "", "rfc must be %s, got %q", wantRFC, doc.RFC)
	}
	if len(doc.Rows) == 0 {
		rep.add(file, "", "conformance table is empty")
	}
	ids := map[string]int{}
	prefix := "T89-"
	if wantRFC == "9887" {
		prefix = "T98-"
	}
	for i, row := range doc.Rows {
		if row.ID == "" {
			rep.add(file, fmt.Sprintf("index-%d", i), "missing id")
			continue
		}
		if !conformanceIDRe.MatchString(row.ID) || !strings.HasPrefix(row.ID, prefix) {
			rep.add(file, row.ID, "id must match %s* T89/T98 form", prefix)
		}
		if prev, ok := ids[row.ID]; ok {
			rep.add(file, row.ID, "duplicate conformance id (first at index %d)", prev)
		} else {
			ids[row.ID] = i
		}
		if row.Level == "" {
			rep.add(file, row.ID, "missing level")
		}
		if row.Requirement == "" {
			rep.add(file, row.ID, "missing requirement")
		}
		if row.Section == "" {
			rep.add(file, row.ID, "missing section")
		}
		if _, ok := validConformanceStatuses[row.Status]; !ok {
			rep.add(file, row.ID, "invalid status %q", row.Status)
		}
		if row.Status == StatusNotStarted && len(row.Evidence) != 0 {
			rep.add(file, row.ID, "NOT_STARTED rows must have empty evidence")
		}
	}
}

func validateConformanceIDUniqueness(rep *Report, tables ...*ConformanceRegistry) {
	seen := map[string]string{}
	for _, table := range tables {
		if table == nil {
			continue
		}
		file := RFC8907Path
		if table.RFC == "9887" {
			file = RFC9887Path
		}
		for _, row := range table.Rows {
			if prev, ok := seen[row.ID]; ok {
				rep.add(file, row.ID, "duplicate conformance id also in %s", prev)
			} else {
				seen[row.ID] = file
			}
		}
	}
}

func checkOperationContractCoverage(rep *Report, contract []string, doc *OperationRegistry) {
	have := map[string]struct{}{}
	for _, op := range doc.Operations {
		have[op.ID] = struct{}{}
	}
	for _, id := range contract {
		if _, ok := have[id]; !ok {
			rep.add(OperationsPath, id, "contract operation is missing from the registry")
		}
	}
}

func checkConformanceContractCoverage(rep *Report, contract []string, tables ...*ConformanceRegistry) {
	have := map[string]struct{}{}
	for _, table := range tables {
		if table == nil {
			continue
		}
		for _, row := range table.Rows {
			have[row.ID] = struct{}{}
		}
	}
	for _, id := range contract {
		if _, ok := have[id]; !ok {
			file := RFC8907Path
			if strings.HasPrefix(id, "T98-") {
				file = RFC9887Path
			}
			rep.add(file, id, "unreferenced mandatory conformance row: present in %s but missing from the registry", ConformanceDocPath)
		}
	}
}

// CheckReleaseStatuses fails MUST / MUST NOT / PROJECT MUST rows that are not PASS
// or an allowed deprecation disposition. Structural CI does not call this.
func CheckReleaseStatuses(tables ...*ConformanceRegistry) []Issue {
	var issues []Issue
	for _, table := range tables {
		if table == nil {
			continue
		}
		file := RFC8907Path
		if table.RFC == "9887" {
			file = RFC9887Path
		}
		for _, row := range table.Rows {
			if !row.Mandatory() {
				continue
			}
			switch row.Status {
			case StatusPass, StatusNADeprecated:
				continue
			default:
				issues = append(issues, Issue{
					File:    file,
					ID:      row.ID,
					Message: fmt.Sprintf("release validation: mandatory %s row has status %s", row.Level, row.Status),
				})
			}
		}
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].ID < issues[j].ID })
	return issues
}
