package config

import (
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("schema_version: 1\n"))
	f.Add([]byte(""))
	f.Add([]byte("schema_version: 2\n"))
	f.Add([]byte("foo: bar\n"))
	f.Add([]byte("schema_version: 1\nlisteners:\n  legacy_tacacs: {enabled: false}\n"))
	f.Add([]byte("schema_version: 2\nlisteners:\n  tacacs:\n    legacy: {enabled: false}\n"))
	f.Add([]byte("schema_version: 1\nlisteners:\n  radius:\n    access: {enabled: true}\n"))
	f.Add([]byte("schema_version: 2\nlisteners:\n  legacy_tacacs: {enabled: false}\n"))
	f.Add([]byte("schema_version: 1\n&alias\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			data = data[:64*1024]
		}
		doc, err := Parse(data)
		if err != nil {
			if strings.Contains(err.Error(), "unit-test-obs-") {
				t.Fatalf("canary in parse error: %v", err)
			}
			return
		}
		if doc == nil {
			t.Fatal("nil document")
		}
		if doc.SchemaVersion != SchemaVersionV1 && doc.SchemaVersion != SchemaVersionV2 {
			t.Fatalf("schema %d", doc.SchemaVersion)
		}
	})
}
