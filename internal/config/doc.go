// Package config decodes, normalizes, and cross-validates versioned YAML baselines.
//
// Parse and Load accept schema_version 1 and 2. Version 1 is migrated in
// memory to the same named listener structs as version 2; the source file
// is never rewritten. Document.SchemaVersion records the source version.
// RADIUS listener fields exist and default to enabled:false; they are not
// started by the current process.
//
// Validate checks references, limits, command patterns, and fail-closed
// client match. Secret material is referenced (file or environment), never
// stored as a string on Document. ReadSecret loads bytes into credentials
// holders.
package config
