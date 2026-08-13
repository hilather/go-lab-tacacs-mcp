// Package parity is the REST/MCP equivalence harness (API_PARITY §12, P11.5).
//
// Tests invoke the same operation through the registry, REST, and MCP against
// isolated identical fixtures. Adapters are compared on domain meaning
// (result, revision, events, error code, redaction), not wire identity.
// events.subscribe is PARITY_DIFFERENT_BINDING: REST SSE bodies versus MCP
// URI notify plus events.list pull.
package parity
