# TacLab web UI

React + TypeScript strict + Vite + TanStack Query + React Router. Generated types live in `src/generated/api.ts` (from `tools/generate`).

The UI talks only to public REST. Browser auth is `POST /api/v1/session` → HttpOnly `taclab_session` + CSRF cookie. A cold load (new tab, or a document that has the cookie but no `sessionStorage` principal cache) calls `GET /api/v1/session` for the real scopes. The bearer token is never written to `localStorage` or `sessionStorage`. Mutations send `X-CSRF-Token` and `If-Match: "revision-N"`.

Pages: sign-in, status, users, groups, clients, tokens (one-time copy/acknowledge), events, authentication test, RADIUS authentication test, policy explain, RADIUS policy explain, config/export/validate/reload/reset, about. The signed-in chrome is a dark grouped rail (Lab / Directory / TACACS+ / RADIUS). Events is a live AAA log. RADIUS pages use generated REST types only and do not advertise complete RADIUS.

Users page badges `Must change login` / `Must change enable` next to Enabled and editor checkboxes for those flags (generated `User` fields only). Authentication test displays status `must_change` after a successful verify plus the applicable flag; that value is not a TACACS or RADIUS packet status.

`web/go.mod` is a nested-module fence so parent `go test ./...` does not walk `node_modules`. Do not import `github.com/hilather/go-lab-tacacs-mcp/web` from the parent module. `//go:embed` cannot leave a module, so `make web-build` copies `web/dist` into `internal/ui/dist`. The committed fallback is `internal/ui/stub`.

## Scripts

```bash
npm --prefix web test          # Vitest + Testing Library
npm --prefix web run typecheck
npm --prefix web run lint
npm --prefix web run build     # hashed assets + bundle budget
npm --prefix web run test:e2e  # Playwright keyboard/session + remaining-page smoke
```

Dev server proxies `/api`, `/health`, and `/mcp` to `http://127.0.0.1:8080`.
