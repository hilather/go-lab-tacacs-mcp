// Package events is the bounded in-memory event and accounting ring.
//
// Accounting SUCCESS is returned only after a record is accepted here.
// The ring overwrites the oldest entry and increments an overwrite counter.
// Cursor reads (events.list) and a non-blocking stdout JSON sink live here.
// REST SSE body fan-out uses Subscribe (event channel + dropped signal).
// Slow subscribers are detached; Accept never blocks. MCP listen remains later.
package events
