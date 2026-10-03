package config

import (
	"strings"
	"testing"
)

func TestAdminHTTPRejectsUnsupportedTLS(t *testing.T) {
	for _, schema := range []int{SchemaVersion, SchemaVersionV2} {
		doc := defaultDocument()
		doc.SchemaVersion = schema
		doc.Listeners.SecureTACACS.Enabled = false
		doc.Listeners.HTTP.TLS.Enabled = true
		err := Validate(&doc)
		if err == nil || !strings.Contains(err.Error(), "listeners.http.tls.enabled") {
			t.Fatalf("schema %d: unsupported HTTP TLS accepted: %v", schema, err)
		}
	}
}
