// Package events is the bounded in-memory event and accounting ring.
//
// Accounting SUCCESS is returned only after a record is accepted here.
// This skeleton is a monotonic ring with overwrite; REST SSE fan-out and
// MCP listen notifications are later work.
package events
