// Package events is the bounded in-memory event and accounting ring.
//
// Accounting SUCCESS is returned only after a record is accepted here.
// The ring overwrites the oldest entry and increments an overwrite counter.
// Cursor reads (events.list) and a non-blocking stdout JSON sink live here.
// Query may AND optional protocol, listener role, packet code, and outcome
// onto the existing category filter. RADIUS Acct-Session-Id is AcctSessionID
// (string); TACACS SessionID stays uint32.
// REST SSE body fan-out uses Subscribe (event channel + dropped signal).
// MCP listen uses the same Subscribe for URI-only resources/updated (C8).
// Slow subscribers are detached; Accept never blocks.
package events
