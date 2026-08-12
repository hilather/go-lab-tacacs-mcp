// Package state owns the immutable baseline, the memory-only overlay, and
// the atomically published snapshot.
//
// Reload is explicit (caller-invoked). There is no file watcher.
package state
