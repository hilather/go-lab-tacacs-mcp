package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	OperationsPath           = "api/operations.yaml"
	RFC8907Path              = "testdata/conformance/rfc8907.yaml"
	RFC9887Path              = "testdata/conformance/rfc9887.yaml"
	RFC2865Path              = "testdata/conformance/rfc2865.yaml"
	RFC2866Path              = "testdata/conformance/rfc2866.yaml"
	RFC2869Path              = "testdata/conformance/rfc2869.yaml"
	RFC3579Path              = "testdata/conformance/rfc3579.yaml"
	RFC5080Path              = "testdata/conformance/rfc5080.yaml"
	ProjectRADIUSPath        = "testdata/conformance/project-radius.yaml"
	ConformanceDocPath       = "docs/TACACS_CONFORMANCE.md"
	RadiusConformanceDocPath = "docs/RADIUS_CONFORMANCE.md"
	ParityDocPath            = "docs/API_PARITY.md"
	GeneratedParity          = "docs/generated/api-parity.md"
	GeneratedConformance     = "docs/generated/conformance.md"
)

// ConformanceSpec names one checked-in conformance registry file.
type ConformanceSpec struct {
	Path   string
	RFC    string
	Prefix string
}

// ConformanceSpecs is the explicit list of registries ValidateRoot loads.
// Do not replace this with a directory glob.
var ConformanceSpecs = []ConformanceSpec{
	{Path: RFC8907Path, RFC: "8907", Prefix: "T89-"},
	{Path: RFC9887Path, RFC: "9887", Prefix: "T98-"},
	{Path: RFC2865Path, RFC: "2865", Prefix: "R65-"},
	{Path: RFC2866Path, RFC: "2866", Prefix: "R66-"},
	{Path: RFC2869Path, RFC: "2869", Prefix: "R69-"},
	{Path: RFC3579Path, RFC: "3579", Prefix: "R79-"},
	{Path: RFC5080Path, RFC: "5080", Prefix: "R80-"},
	{Path: ProjectRADIUSPath, RFC: "PROJECT", Prefix: "PRJ-"},
}

// FindRoot walks start and its parents until go.mod is found.
func FindRoot(start string) (string, error) {
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

// RegistriesPresent reports whether the checked-in registry files exist.
func RegistriesPresent(root string) bool {
	required := []string{OperationsPath}
	for _, spec := range ConformanceSpecs {
		required = append(required, spec.Path)
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			return false
		}
	}
	return true
}

// FileForRFC returns the registry path for an rfc: field value.
func FileForRFC(rfc string) string {
	for _, spec := range ConformanceSpecs {
		if spec.RFC == rfc {
			return spec.Path
		}
	}
	return ""
}

// FileForConformanceID returns the registry path whose prefix matches id.
func FileForConformanceID(id string) string {
	for _, spec := range ConformanceSpecs {
		if strings.HasPrefix(id, spec.Prefix) {
			return spec.Path
		}
	}
	return RFC8907Path
}

// PrefixForRFC returns the required row-id prefix for an rfc: field value.
func PrefixForRFC(rfc string) string {
	for _, spec := range ConformanceSpecs {
		if spec.RFC == rfc {
			return spec.Prefix
		}
	}
	return ""
}
