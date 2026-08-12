// Package config decodes and normalizes versioned YAML baselines.
//
// This package stops at a typed, defaulted Document. It does not compile
// overlays, client-match indexes, or a published snapshot.
//
// Secret material is referenced (file or environment), never stored as a
// string on Document. ReadSecret loads bytes into credentials holders.
package config
