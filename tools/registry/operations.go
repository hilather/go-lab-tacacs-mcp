package registry

import (
	"fmt"
)

const (
	ParityRequired         = "PARITY_REQUIRED"
	RESTOnlyProtocol       = "REST_ONLY_PROTOCOL"
	MCPOnlyProtocol        = "MCP_ONLY_PROTOCOL"
	ParityDifferentBinding = "PARITY_DIFFERENT_BINDING"
	ExemptByADR            = "EXEMPT_BY_ADR"
)

var validDispositions = map[string]struct{}{
	ParityRequired:         {},
	RESTOnlyProtocol:       {},
	MCPOnlyProtocol:        {},
	ParityDifferentBinding: {},
	ExemptByADR:            {},
}

var knownScopes = map[string]struct{}{
	"state:read":       {},
	"state:write":      {},
	"config:reload":    {},
	"config:export":    {},
	"policy:test":      {},
	"events:read":      {},
	"events:sensitive": {},
	"tokens:manage":    {},
	"runtime:reset":    {},
}

var validIdempotent = map[string]struct{}{
	"true":        {},
	"false":       {},
	"conditional": {},
}

// RESTBinding is the HTTP method and path for an operation.
type RESTBinding struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

// Empty reports whether both method and path are unset.
func (b RESTBinding) Empty() bool {
	return b.Method == "" && b.Path == ""
}

// MCPBinding is the MCP tool, resource, listen, or protocol binding.
type MCPBinding struct {
	Kind          string `yaml:"kind"`
	Name          string `yaml:"name"`
	Resource      string `yaml:"resource,omitempty"`
	PullOperation string `yaml:"pull_operation,omitempty"`
}

// Empty reports whether the binding has no kind, name, or resource.
func (b MCPBinding) Empty() bool {
	return b.Kind == "" && b.Name == "" && b.Resource == ""
}

// Operation is one administrative or protocol capability.
type Operation struct {
	ID           string      `yaml:"id"`
	Description  string      `yaml:"description"`
	Parity       string      `yaml:"parity"`
	Mutating     bool        `yaml:"mutating"`
	Idempotent   string      `yaml:"idempotent"`
	Scopes       []string    `yaml:"scopes"`
	RequestType  string      `yaml:"request_type"`
	ResponseType string      `yaml:"response_type"`
	REST         RESTBinding `yaml:"rest"`
	MCP          MCPBinding  `yaml:"mcp"`
	AuditEvent   string      `yaml:"audit_event"`
	ADR          string      `yaml:"adr,omitempty"`
	Status       string      `yaml:"status"`
}

// OperationRegistry is the decoded api/operations.yaml document.
type OperationRegistry struct {
	SchemaVersion int         `yaml:"schema_version"`
	Title         string      `yaml:"title"`
	Operations    []Operation `yaml:"operations"`
}

// LoadOperations decodes an operations registry YAML file.
func LoadOperations(path string) (*OperationRegistry, error) {
	var doc OperationRegistry
	if err := decodeYAML(path, &doc); err != nil {
		return nil, err
	}
	if doc.SchemaVersion == 0 && len(doc.Operations) == 0 && doc.Title == "" {
		return nil, fmt.Errorf("%s: empty document", path)
	}
	return &doc, nil
}
