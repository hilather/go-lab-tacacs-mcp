# TacLab web UI

Vite + React + TypeScript sources. `web/go.mod` is a nested-module fence so parent `go test ./...` does not walk `node_modules`.

Do not import `github.com/hilather/go-lab-tacacs-mcp/web` from the parent module. `//go:embed` cannot leave a module, so production embed must copy `web/dist` into a parent-module path (for example `internal/ui/dist`) and embed from there. Do not add parent-imported Go packages under `web/`.

If `web/` is added to a `go.work`, exclude `node_modules` from that module’s package walk (`go.mod` `ignore ./node_modules` requires Go 1.25+; this repo is pinned to 1.24.5).
