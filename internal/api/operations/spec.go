package operations

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"gopkg.in/yaml.v3"
)

const operationsYAML = "api/operations.yaml"

// RESTBinding is the HTTP method and path. Adapters consume this; this package
// does not speak HTTP.
type RESTBinding struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

// MCPBinding is the MCP tool, resource, listen, or protocol binding.
type MCPBinding struct {
	Kind          string `yaml:"kind"`
	Name          string `yaml:"name"`
	Resource      string `yaml:"resource,omitempty"`
	PullOperation string `yaml:"pull_operation,omitempty"`
}

// SpecOp is one row from api/operations.yaml.
type SpecOp struct {
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

// Spec is the decoded operation inventory.
type Spec struct {
	SchemaVersion int      `yaml:"schema_version"`
	Title         string   `yaml:"title"`
	Operations    []SpecOp `yaml:"operations"`
}

// LoadSpec decodes an operations.yaml document. Unknown fields are rejected.
func LoadSpec(path string) (*Spec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var spec Spec
	if err := dec.Decode(&spec); err != nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "cannot decode operation registry").
			WithPath(path).
			WithDetail("error", err.Error())
	}
	if spec.SchemaVersion != 1 {
		return nil, domain.NewError(domain.CodeInvalidArgument, "schema_version must be 1").
			WithPath(path).
			WithDetail("got", spec.SchemaVersion)
	}
	if len(spec.Operations) == 0 {
		return nil, domain.NewError(domain.CodeInvalidArgument, "operations table is empty").WithPath(path)
	}
	return &spec, nil
}

// LoadRepoSpec loads api/operations.yaml from the module root that contains start.
func LoadRepoSpec(start string) (*Spec, error) {
	root, err := FindRepoRoot(start)
	if err != nil {
		return nil, err
	}
	return LoadSpec(filepath.Join(root, operationsYAML))
}

// FindRepoRoot walks start and its parents until go.mod is found.
func FindRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", start)
		}
		dir = parent
	}
}
