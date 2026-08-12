// Package events is the bounded in-memory event and accounting ring.
//
// Accounting SUCCESS is returned only after a record is accepted here.
// The ring overwrites the oldest entry and increments an overwrite counter.
// Cursor reads (events.list) and a non-blocking stdout JSON sink live here.
// REST SSE body fan-out and MCP listen notifications are later adapters;
// they must not block Accept.
package events
