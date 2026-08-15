package registry

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GenerateDocs writes the human-readable inventories under docs/generated.
func GenerateDocs(root string, ops *OperationRegistry, tables ...*ConformanceRegistry) error {
	dir := filepath.Join(root, "docs", "generated")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, GeneratedParity), []byte(renderParity(ops)), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, GeneratedConformance), []byte(renderConformance(tables...)), 0o644)
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
	b.WriteString("# Generated TACACS+ and RADIUS conformance inventory\n\n")
	b.WriteString("Do not hand-edit this file. Run `make generate`.\n\n")
	sources := make([]string, 0, len(ConformanceSpecs))
	for _, spec := range ConformanceSpecs {
		sources = append(sources, "`"+spec.Path+"`")
	}
	b.WriteString("Sources: ")
	b.WriteString(strings.Join(sources, ", "))
	b.WriteString("\n\n")
	tacacs, radius := splitConformanceTables(tables)
	b.WriteString(renderQualificationSummary(tacacs...))
	b.WriteString(renderRADIUSQualificationSummary(radius...))
	for _, table := range tables {
		if table == nil {
			continue
		}
		if table.RFC == "PROJECT" {
			b.WriteString("## Project RADIUS\n\n")
		} else {
			b.WriteString("## RFC ")
			b.WriteString(table.RFC)
			b.WriteString("\n\n")
		}
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

func splitConformanceTables(tables []*ConformanceRegistry) (tacacs, radius []*ConformanceRegistry) {
	for _, table := range tables {
		if table == nil {
			continue
		}
		switch table.RFC {
		case "8907", "9887":
			tacacs = append(tacacs, table)
		default:
			radius = append(radius, table)
		}
	}
	return tacacs, radius
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
		b.WriteString(" mandatory rows `PASS`) |\n")
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

func renderRADIUSQualificationSummary(tables ...*ConformanceRegistry) string {
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
			case StatusPass, StatusNADeprecated, StatusDeferredMAY:
				mustPass++
			default:
				mustOpen++
				openMust = append(openMust, row.ID+"="+row.Status)
			}
		}
	}
	var b strings.Builder
	b.WriteString("## RADIUS qualification summary\n\n")
	b.WriteString("| Gate | Result |\n|---|---|\n")
	if mustOpen == 0 && mustTotal > 0 {
		b.WriteString("| RADIUS / project MVP rows | **PASS** (")
		b.WriteString(strconv.Itoa(mustPass))
		b.WriteString("/")
		b.WriteString(strconv.Itoa(mustTotal))
		b.WriteString(" mandatory rows `PASS` or deferred with ADR evidence) |\n")
	} else {
		b.WriteString("| RADIUS / project MVP rows | **OPEN** (")
		b.WriteString(strconv.Itoa(mustOpen))
		b.WriteString(" unresolved")
		if len(openMust) > 0 {
			b.WriteString(": ")
			b.WriteString(escapeCell(strings.Join(openMust, ", ")))
		}
		b.WriteString(") |\n")
	}
	b.WriteString("| Advertised completeness | **Do not claim complete RADIUS** while Access-Challenge is deferred, external radclient is skipped, or any MVP row lacks evidence |\n")
	b.WriteString("| Independent software peer | `internal/radius/testclient` (separate codec) |\n")
	b.WriteString("| External radclient / Cisco IOL | **SKIP** unless recorded in `docs/INTEROP.md`; a skip is not RADIUS PASS |\n\n")
	if mustOpen != 0 {
		b.WriteString("RADIUS MVP rows remain open until linked evidence exists. Do **not** advertise complete RADIUS. TACACS 1.0 `-release` still gates only RFC 8907/9887.\n\n")
	} else {
		b.WriteString("RADIUS MVP MUST rows are evidenced or deferred with an ADR. Access-Challenge stays `DEFERRED_MAY`. External radclient/device interop is not claimed. Do **not** advertise complete RADIUS. TACACS 1.0 `-release` still gates only RFC 8907/9887.\n\n")
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
