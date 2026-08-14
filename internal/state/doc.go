// Package state owns the immutable baseline, the memory-only overlay, and
// the atomically published snapshot.
//
// Compile attaches the TACACS ClientIndex, RADIUS access/accounting LPM
// indexes, and an empty dictionary placeholder (later PRs fill the hook).
// Reload is explicit (caller-invoked). There is no file watcher.
package state
