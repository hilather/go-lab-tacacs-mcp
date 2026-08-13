// Command generate writes checked-in generated files from pinned inputs.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/rest"
)

// toolchainMarkdown must stay bit-identical to docs/generated/toolchain.md.
// The official MCP Go SDK is a compile-time dependency (ADR 0011 adopted).
const toolchainMarkdown = `# Generated toolchain record

Do not hand-edit this file. Run ` + "`make generate`" + `.

| Pin | Value |
|---|---|
| Go module | ` + "`github.com/hilather/go-lab-tacacs-mcp`" + ` |
| Go version | 1.25.0 |
| Node.js | 22.14.0 |
| npm | 10.9.2 |
| Image | ` + "`ghcr.io/hilather/go-lab-tacacs-mcp`" + ` |
| Image variants (every release) | distroless (` + "`:<tag>`" + `), Ubuntu 24.04 (` + "`:<tag>-ubuntu`" + `), Rocky Linux 9 (` + "`:<tag>-rocky`" + `) |
| MCP specification | 2026-07-28 |
| Official MCP Go SDK | ` + "`github.com/modelcontextprotocol/go-sdk v1.7.0`" + ` (imported; Streamable HTTP 2026-07-28, ADR 0011) |
`

func main() {
	if err := generate("."); err != nil {
		fmt.Fprintf(os.Stderr, "generate: %v\n", err)
		os.Exit(1)
	}
}

func generate(root string) error {
	path := filepath.Join(root, "docs", "generated", "toolchain.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(toolchainMarkdown), 0o644); err != nil {
		return err
	}
	return rest.WriteGenerated(root)
}
