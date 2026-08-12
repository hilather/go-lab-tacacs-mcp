package registry

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	OperationsPath       = "api/operations.yaml"
	RFC8907Path          = "testdata/conformance/rfc8907.yaml"
	RFC9887Path          = "testdata/conformance/rfc9887.yaml"
	ConformanceDocPath   = "docs/TACACS_CONFORMANCE.md"
	ParityDocPath        = "docs/API_PARITY.md"
	GeneratedParity      = "docs/generated/api-parity.md"
	GeneratedConformance = "docs/generated/conformance.md"
)

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
	for _, rel := range []string{OperationsPath, RFC8907Path, RFC9887Path} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			return false
		}
	}
	return true
}
