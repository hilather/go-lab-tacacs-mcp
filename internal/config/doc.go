// Package config decodes and normalizes versioned YAML baselines.
//
// Parse and Load produce a typed, defaulted Document. Secret material is
// referenced (file or environment), never stored as a string on Document.
// ReadSecret loads bytes into credentials holders.
package config
