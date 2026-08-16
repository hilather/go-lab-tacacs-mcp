package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

func TestSnapshotDictionaryBuiltinWithoutOperatorFiles(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	s := m.Snapshot()
	if s.DictionaryVersion() != attribute.DictionaryVersion {
		t.Fatalf("version=%q", s.DictionaryVersion())
	}
	if _, ok := s.Dictionary().View().LookupName("User-Name"); !ok {
		t.Fatal("builtin missing")
	}
}

func TestSnapshotCompilesOperatorDictionary(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "juniper.yaml")
	if err := os.WriteFile(path, []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes:
  - name: Juniper-Local-User-Name
    vendor_type: 1
    kind: text
    allowed_in: [access_accept]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := mustMgr(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: lab-juniper
    file: `+path+`
`)
	s := m.Snapshot()
	if !strings.HasPrefix(s.DictionaryVersion(), attribute.DictionaryVersion+"+op:") {
		t.Fatalf("version=%q", s.DictionaryVersion())
	}
	def, ok := s.Dictionary().View().LookupName("Juniper-Local-User-Name")
	if !ok || def.Source != "operator:lab-juniper" {
		t.Fatalf("def=%+v ok=%v", def, ok)
	}
}

func TestReloadInvalidOperatorDictionaryKeepsSnapshot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes:
  - name: Juniper-Local-User-Name
    vendor_type: 1
    kind: text
    allowed_in: [access_accept]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := mustMgr(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: lab-juniper
    file: `+good+`
`)
	before := m.Snapshot()
	rev := before.Revision
	wantVer := before.DictionaryVersion()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte(`schema_version: 1
vendor: {id: 9, name: Cisco}
attributes:
  - name: Stolen
    vendor_type: 1
    kind: text
    allowed_in: [access_accept]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: stolen
    file: `+bad+`
`)
	if _, err := m.Reload(doc, &rev); err == nil {
		t.Fatal("reserved vendor must fail compile")
	} else if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("err=%v", err)
	}
	if m.Snapshot() != before {
		t.Fatal("invalid dictionary must keep previous snapshot")
	}
	if m.Snapshot().DictionaryVersion() != wantVer {
		t.Fatalf("version moved: %q", m.Snapshot().DictionaryVersion())
	}
}

func TestNewRejectsReservedOperatorName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "cisco.yaml")
	if err := os.WriteFile(path, []byte(`schema_version: 1
vendor: {id: 2636, name: Juniper}
attributes:
  - name: Cisco-AVPair
    vendor_type: 1
    kind: text
    allowed_in: [access_accept]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_dictionaries:
  - id: stolen
    file: `+path+`
`), Options{})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reserved") {
		t.Fatalf("err=%v", err)
	}
}
