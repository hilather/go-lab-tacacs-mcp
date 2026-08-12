package registry

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	StatusNotStarted          = "NOT_STARTED"
	StatusInProgress          = "IN_PROGRESS"
	StatusPass                = "PASS"
	StatusNADeprecated        = "N/A_RFC_DEPRECATED"
	StatusDeferredMAY         = "DEFERRED_MAY"
	StatusDispositionedSHOULD = "DISPOSITIONED_SHOULD"
	StatusFail                = "FAIL"
)

var validConformanceStatuses = map[string]struct{}{
	StatusNotStarted:          {},
	StatusInProgress:          {},
	StatusPass:                {},
	StatusNADeprecated:        {},
	StatusDeferredMAY:         {},
	StatusDispositionedSHOULD: {},
	StatusFail:                {},
}

// ConformanceRow is one T89-* or T98-* checklist item.
type ConformanceRow struct {
	ID               string   `yaml:"id"`
	Section          string   `yaml:"section"`
	SectionTitle     string   `yaml:"section_title"`
	Level            string   `yaml:"level"`
	Requirement      string   `yaml:"requirement"`
	EvidenceRequired string   `yaml:"evidence_required"`
	Status           string   `yaml:"status"`
	Evidence         []string `yaml:"evidence"`
}

// ConformanceRegistry is one RFC row table.
type ConformanceRegistry struct {
	SchemaVersion int              `yaml:"schema_version"`
	RFC           string           `yaml:"rfc"`
	Title         string           `yaml:"title"`
	Rows          []ConformanceRow `yaml:"rows"`
}

// LoadConformance decodes a conformance registry YAML file.
func LoadConformance(path string) (*ConformanceRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc ConformanceRegistry
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &doc, nil
}

// Mandatory reports whether the row is a 1.0 release-blocking requirement.
func (r ConformanceRow) Mandatory() bool {
	switch r.Level {
	case "MUST", "MUST NOT", "PROJECT MUST", "MUST/PROJECT MUST":
		return true
	default:
		return false
	}
}
