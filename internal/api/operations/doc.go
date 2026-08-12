// Package operations is the canonical administrative operation registry.
//
// REST and MCP adapters invoke this package. They must not implement
// validation, scopes, snapshot reads, or domain errors themselves.
//
// api/operations.yaml is the enumerated inventory. Every YAML operation is
// registered here. system.status.get, system.build.get, and policy.evaluate
// are implemented; remaining handlers return unavailable until later work
// fills them.
package operations
