// Package rest is the HTTP adapter for the operation registry.
//
// It serves health probes, the versioned /api/v1 surface, SSE event
// bodies, and /api/openapi.json. Adapters invoke operations and never
// the MCP package. Browser cookie mutations require CSRF.
// cookie_secure follows listeners.http.tls.enabled.
package rest
