package registry

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GenerateDocs writes the human-readable inventories under docs/generated.
func GenerateDocs(root string, ops *OperationRegistry, r89, r98 *ConformanceRegistry) error {
	dir := filepath.Join(root, "docs", "generated")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, GeneratedParity), []byte(renderParity(ops)), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, GeneratedConformance), []byte(renderConformance(r89, r98)), 0o644)
}

func renderParity(ops *OperationRegistry) string {
	var b strings.Builder
	b.WriteString("# Generated REST/MCP operation inventory\n\n")
	b.WriteString("Do not hand-edit this file. Run `make generate`.\n\n")
	b.WriteString("Source: `api/operations.yaml`\n\n")
	b.WriteString("| Operation ID | Description | Disposition | Scopes | REST | MCP | Request | Response | Mutating | Idempotent | Status |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|\n")
	if ops == nil {
		return b.String()
	}
	for _, op := range ops.Operations {
		b.WriteString("| ")
		b.WriteString(escapeCell(op.ID))
		b.WriteString(" | ")
		b.WriteString(escapeCell(op.Description))
		b.WriteString(" | ")
		b.WriteString(escapeCell(op.Parity))
		b.WriteString(" | ")
		b.WriteString(escapeCell(strings.Join(op.Scopes, ", ")))
		b.WriteString(" | ")
		b.WriteString(escapeCell(formatREST(op.REST)))
		b.WriteString(" | ")
		b.WriteString(escapeCell(formatMCP(op.MCP)))
		b.WriteString(" | ")
		b.WriteString(escapeCell(op.RequestType))
		b.WriteString(" | ")
		b.WriteString(escapeCell(op.ResponseType))
		b.WriteString(" | ")
		b.WriteString(strconv.FormatBool(op.Mutating))
		b.WriteString(" | ")
		b.WriteString(escapeCell(op.Idempotent))
		b.WriteString(" | ")
		b.WriteString(escapeCell(op.Status))
		b.WriteString(" |\n")
	}
	b.WriteByte('\n')
	return b.String()
}

func renderConformance(tables ...*ConformanceRegistry) string {
	var b strings.Builder
	b.WriteString("# Generated TACACS+ conformance inventory\n\n")
	b.WriteString("Do not hand-edit this file. Run `make generate`.\n\n")
	b.WriteString("Sources: `testdata/conformance/rfc8907.yaml`, `testdata/conformance/rfc9887.yaml`\n\n")
	b.WriteString("Status columns start `NOT_STARTED` with empty evidence.\n\n")
	for _, table := range tables {
		if table == nil {
			continue
		}
		b.WriteString("## RFC ")
		b.WriteString(table.RFC)
		b.WriteString("\n\n")
		if table.Title != "" {
			b.WriteString(table.Title)
			b.WriteString("\n\n")
		}
		b.WriteString("| ID | Level | Status | Requirement |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, row := range table.Rows {
			b.WriteString("| ")
			b.WriteString(escapeCell(row.ID))
			b.WriteString(" | ")
			b.WriteString(escapeCell(row.Level))
			b.WriteString(" | ")
			b.WriteString(escapeCell(row.Status))
			b.WriteString(" | ")
			b.WriteString(escapeCell(row.Requirement))
			b.WriteString(" |\n")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func formatREST(b RESTBinding) string {
	if b.Empty() {
		return ""
	}
	return strings.TrimSpace(b.Method + " " + b.Path)
}

func formatMCP(b MCPBinding) string {
	if b.Empty() {
		return ""
	}
	parts := make([]string, 0, 4)
	if b.Kind != "" {
		parts = append(parts, b.Kind)
	}
	if b.Name != "" {
		parts = append(parts, b.Name)
	}
	if b.Resource != "" {
		parts = append(parts, b.Resource)
	}
	if b.PullOperation != "" {
		parts = append(parts, "pull "+b.PullOperation)
	}
	return strings.Join(parts, " ")
}

func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
