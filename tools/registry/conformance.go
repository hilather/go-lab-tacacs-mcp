package registry

import (
	"fmt"
	"strings"
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

// ConformanceRow is one T89-*, T98-*, R65-*, R66-*, R69-*, R79-*, R80-*, or PRJ-* checklist item.
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
	var doc ConformanceRegistry
	if err := decodeYAML(path, &doc); err != nil {
		return nil, err
	}
	if doc.SchemaVersion == 0 && doc.RFC == "" && len(doc.Rows) == 0 {
		return nil, fmt.Errorf("%s: empty document", path)
	}
	return &doc, nil
}

// Mandatory reports whether the row is a 1.0 release-blocking requirement.
func (r ConformanceRow) Mandatory() bool {
	level := r.Level
	if strings.Contains(level, "CLIENT-ROLE") || strings.Contains(level, "OPERATOR") {
		return false
	}
	if strings.Contains(level, "if PSK implemented") {
		return false
	}
	return strings.Contains(level, "MUST")
}
