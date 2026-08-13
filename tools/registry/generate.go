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
	b.WriteString(renderQualificationSummary(tables...))
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
		b.WriteString("| ID | Level | Status | Requirement | Evidence |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, row := range table.Rows {
			b.WriteString("| ")
			b.WriteString(escapeCell(row.ID))
			b.WriteString(" | ")
			b.WriteString(escapeCell(row.Level))
			b.WriteString(" | ")
			b.WriteString(escapeCell(row.Status))
			b.WriteString(" | ")
			b.WriteString(escapeCell(row.Requirement))
			b.WriteString(" | ")
			b.WriteString(escapeCell(strings.Join(row.Evidence, "; ")))
			b.WriteString(" |\n")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func renderQualificationSummary(tables ...*ConformanceRegistry) string {
	var mustTotal, mustPass, mustOpen int
	openMust := []string{}
	for _, table := range tables {
		if table == nil {
			continue
		}
		for _, row := range table.Rows {
			if !row.Mandatory() {
				continue
			}
			mustTotal++
			switch row.Status {
			case StatusPass, StatusNADeprecated:
				mustPass++
			default:
				mustOpen++
				openMust = append(openMust, row.ID+"="+row.Status)
			}
		}
	}
	var b strings.Builder
	b.WriteString("## Qualification summary\n\n")
	b.WriteString("| Gate | Result |\n|---|---|\n")
	if mustOpen == 0 {
		b.WriteString("| RFC `MUST` / `MUST NOT` / `PROJECT MUST` | **PASS** (")
		b.WriteString(strconv.Itoa(mustPass))
		b.WriteString("/")
		b.WriteString(strconv.Itoa(mustTotal))
		b.WriteString(" `PASS` or `N/A_RFC_DEPRECATED`) |\n")
	} else {
		b.WriteString("| RFC `MUST` / `MUST NOT` / `PROJECT MUST` | **OPEN** (")
		b.WriteString(strconv.Itoa(mustOpen))
		b.WriteString(" unresolved: ")
		b.WriteString(escapeCell(strings.Join(openMust, ", ")))
		b.WriteString(") |\n")
	}
	b.WriteString("| Independent software peer | `internal/tacacs/testclient` (separate codec) |\n")
	b.WriteString("| Cisco / second-NOS device interop | **SKIP** — no lab hardware; see `docs/INTEROP.md` |\n")
	b.WriteString("| External TLS PSK / RPK | `DEFERRED_MAY` ([ADR 0006](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0006-external-psk-rpk.md)); T98-OPT-002/003/004 stay `NOT_STARTED` |\n\n")
	if mustOpen != 0 {
		b.WriteString("Do **not** claim complete TACACS+ while a mandatory row is open.\n\n")
	} else {
		b.WriteString("Mandatory RFC 8907/9887 server rows are qualified with linked evidence IDs. Device-family interop is not claimed.\n\n")
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
