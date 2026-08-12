// Package policy compiles authorization matchers and evaluates session/service
// and command requests on separate first-match walks.
//
// A service permit never authorizes a non-empty cmd. A command rule never
// decides a session request. Each evaluator default-denies independently.
// Regular expressions are compiled when the Engine is built, never per request.
//
// This package must not import HTTP, MCP, TACACS packet types, or YAML syntax
// types. Normalized config objects are the compile input.
package policy
