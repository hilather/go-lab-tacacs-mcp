package credentials

import (
	"strings"
	"testing"
)

func FuzzCanonicalUsername(f *testing.F) {
	f.Add("alice")
	f.Add("ALICE")
	f.Add("")
	f.Add("user@example.com")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, raw string) {
		out, err := CanonicalUsername(raw)
		if err != nil {
			if strings.Contains(err.Error(), raw) && raw != "" && !strings.Contains(raw, "invalid") {
				// Error text must not echo arbitrary input.
				if len(raw) > 8 && strings.Contains(err.Error(), raw[:8]) {
					t.Fatalf("username echoed: %q", err)
				}
			}
			return
		}
		if out == "" {
			t.Fatal("empty canonical")
		}
	})
}
