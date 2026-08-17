package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

const juniperOperatorYAML = `schema_version: 1
vendor:
  id: 2636
  name: Juniper
attributes:
  - name: Juniper-Local-User-Name
    vendor_type: 1
    kind: text
    cardinality: single
    sensitivity: restricted
    allowed_in: [access_accept]
`

func TestCompileRADIUSDictionaryMergesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "juniper.yaml")
	if err := os.WriteFile(path, []byte(juniperOperatorYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: lab-juniper
    file: `+path+`
`)
	d, err := CompileRADIUSDictionary(doc)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version() == attribute.DictionaryVersion || !strings.Contains(d.Version(), "lab-juniper") {
		t.Fatalf("version=%q", d.Version())
	}
	if _, ok := d.LookupName("Juniper-Local-User-Name"); !ok {
		t.Fatal("missing operator attr")
	}
}

func TestCompileRADIUSDictionarySkipsDisabled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "juniper.yaml")
	if err := os.WriteFile(path, []byte(juniperOperatorYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: lab-juniper
    file: `+path+`
    enabled: false
`)
	d, err := CompileRADIUSDictionary(doc)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version() != attribute.DictionaryVersion {
		t.Fatalf("disabled file must keep builtin version: %q", d.Version())
	}
	if _, ok := d.LookupName("Juniper-Local-User-Name"); ok {
		t.Fatal("disabled file must not merge")
	}
}

func TestCompileRADIUSDictionaryMissingFile(t *testing.T) {
	t.Parallel()
	doc := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: missing
    file: /etc/taclab/dicts/does-not-exist.yaml
`)
	_, err := CompileRADIUSDictionary(doc)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "readable") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileRADIUSDictionaryRejectsDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	doc := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: dir
    file: `+dir+`
`)
	_, err := CompileRADIUSDictionary(doc)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "directory") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileRADIUSDictionaryRejectsSymlinkWhenStrict(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	real := filepath.Join(dir, "juniper.yaml")
	if err := os.WriteFile(real, []byte(juniperOperatorYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	doc := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: lab-juniper
    file: `+link+`
`)
	if !doc.Security.StrictSecretFiles {
		t.Fatal("strict files should default on")
	}
	_, err := CompileRADIUSDictionary(doc)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompileRADIUSDictionaryRejectsReservedVendorFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ms.yaml")
	body := `schema_version: 1
vendor: {id: 311, name: Microsoft}
attributes:
  - name: Stolen
    vendor_type: 1
    kind: text
    allowed_in: [access_accept]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: stolen
    file: `+path+`
`)
	_, err := CompileRADIUSDictionary(doc)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reserved") {
		t.Fatalf("err=%v", err)
	}
}

func mustParse(t *testing.T, yaml string) *Document {
	t.Helper()
	doc, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
