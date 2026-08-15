// Package operations is the canonical administrative operation registry.
//
// REST and MCP adapters invoke this package. They must not implement
// validation, scopes, snapshot reads, or domain errors themselves.
//
// api/operations.yaml is the enumerated inventory. Every YAML operation is
// registered here. Implemented handlers cover status, build, config, runtime
// reset, user/group/client/token CRUD, policy.evaluate, authentication.test,
// radius.access.test, radius.policy.evaluate, radius.attributes.list,
// events.list, events.subscribe (scope gate; SSE/listen framing stays in the
// adapters), and session.create/delete. MCP protocol rows are adapter-only.
package operations
