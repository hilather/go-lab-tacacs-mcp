# TacLab web UI

React + TypeScript strict + Vite + TanStack Query + React Router. Generated types live in `src/generated/api.ts` (from `tools/generate`).

The UI talks only to public REST. Browser auth is `POST /api/v1/session` → HttpOnly `taclab_session` + CSRF cookie. The bearer token is never written to `localStorage` or `sessionStorage`.

`web/go.mod` is a nested-module fence so parent `go test ./...` does not walk `node_modules`. Do not import `github.com/hilather/go-lab-tacacs-mcp/web` from the parent module. `//go:embed` cannot leave a module, so `make web-build` copies `web/dist` into `internal/ui/dist`. The committed fallback is `internal/ui/stub`.

## Scripts

```bash
npm --prefix web test          # Vitest + Testing Library
npm --prefix web run typecheck
npm --prefix web run lint
npm --prefix web run build     # hashed assets + bundle budget
npm --prefix web run test:e2e  # Playwright keyboard/session smoke
```

Dev server proxies `/api`, `/health`, and `/mcp` to `http://127.0.0.1:8080`.
