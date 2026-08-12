// Package auth verifies lab static bearer tokens, evaluates scopes, and
// issues UI session cookies with CSRF.
//
// REST and MCP adapters call this package. Operation handlers stay
// HTTP-free and receive an already-authenticated Actor. Lab static bearer
// is EXEMPT_BY_ADR relative to the MCP OAuth protected-resource-metadata
// SHOULD; see docs/decisions/0010-lab-static-bearer.md.
package auth
