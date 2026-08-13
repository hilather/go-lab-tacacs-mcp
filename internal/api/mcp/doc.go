// Package mcp is the Streamable HTTP adapter for the operation registry.
//
// TacLab 1.0 implements MCP 2026-07-28 as a thin JSON-RPC adapter. The
// official Go SDK (v1.7.0) is recorded but not imported (ADR 0011). The
// adapter calls the operation
// registry and never the REST package.
//
// POST /mcp only. GET/DELETE return 405. Lab static bearer is EXEMPT_BY_ADR
// (ADR 0010). subscriptions/listen notifies URIs only; event bodies are
// pulled through taclab.events.list.
package mcp
