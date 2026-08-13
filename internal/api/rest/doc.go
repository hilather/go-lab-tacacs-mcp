// Package rest is the HTTP adapter for the operation registry.
//
// It serves health probes, the versioned /api/v1 surface, SSE
// event bodies, /api/openapi.json, and the embedded React SPA. Adapters
// invoke operations and never the MCP package. Browser cookie mutations
// require CSRF. cookie_secure follows listeners.http.tls.enabled.
// Hashed UI assets are immutable; index.html is no-cache. API, health,
// MCP, and metrics paths are never claimed by the SPA fallback.
package rest
