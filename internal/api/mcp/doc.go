// Package mcp is the Streamable HTTP adapter for the operation registry.
//
// This skeleton is a thin JSON-RPC Streamable HTTP adapter (server/discover
// plus taclab.system.status.get and taclab.policy.evaluate). It invokes
// operations and never the REST adapter. The official Go SDK is not a
// compile-time dependency (Go 1.24 pin); PR-17 replaces this adapter.
package mcp
