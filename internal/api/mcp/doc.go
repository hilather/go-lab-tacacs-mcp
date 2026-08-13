// Package mcp is the Streamable HTTP adapter for the operation registry.
//
// TacLab implements MCP 2026-07-28 Streamable HTTP using the official Go
// SDK (v1.7.0). The adapter still calls the operation registry and never
// the REST package. Lab bearer (ADR 0010) and URI-only
// subscriptions/listen stay in this package.
//
// POST /mcp only. GET/DELETE return 405. Lab static bearer is EXEMPT_BY_ADR
// (ADR 0010). subscriptions/listen notifies URIs only; event bodies are
// pulled through taclab.events.list.
package mcp
