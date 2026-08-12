// Command generate writes checked-in generated files from pinned inputs.
//
// Generators in later PRs replace this stub; check-generated must keep failing
// on drift even while the only output is the toolchain record.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Pins recorded for P0. The official MCP Go SDK is documented here and is not
// a compile-time dependency of this skeleton.
const toolchainMarkdown = `# Generated toolchain record

Do not hand-edit this file. Run ` + "`make generate`" + `.

| Pin | Value |
|---|---|
| Go module | ` + "`github.com/hilather/go-lab-tacacs-mcp`" + ` |
| Go version | 1.24.5 |
| Node.js | 22.14.0 |
| npm | 10.9.2 |
| Image | ` + "`ghcr.io/hilather/go-lab-tacacs-mcp`" + ` |
| MCP specification | 2026-07-28 |
| Official MCP Go SDK baseline | ` + "`github.com/modelcontextprotocol/go-sdk v1.7.0`" + ` (recorded; not required by this skeleton) |
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
	return os.WriteFile(path, []byte(toolchainMarkdown), 0o644)
}
