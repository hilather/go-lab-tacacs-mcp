// Package config decodes, normalizes, and cross-validates versioned YAML baselines.
//
// Parse and Load produce a typed, defaulted Document. Validate checks
// references, limits, command patterns, and fail-closed client match.
// Secret material is referenced (file or environment), never stored as a
// string on Document. ReadSecret loads bytes into credentials holders.
package config
