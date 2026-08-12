package events

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()
	if EncodeCursor(0) != "" {
		t.Fatal("zero cursor")
	}
	n, err := DecodeCursor("")
	if err != nil || n != 0 {
		t.Fatalf("empty: %d %v", n, err)
	}
	cur := EncodeCursor(42)
	if cur == "" || cur == "42" {
		t.Fatalf("cursor should be opaque, got %q", cur)
	}
	got, err := DecodeCursor(cur)
	if err != nil || got != 42 {
		t.Fatalf("roundtrip %q -> %d %v", cur, got, err)
	}
}

func TestCursorRejectsGarbage(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"42", "evt", "evt_xyz", "page-1"} {
		_, err := DecodeCursor(s)
		if err == nil {
			t.Fatalf("accepted %q", s)
		}
		if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeInvalidArgument {
			t.Fatalf("%q: %v", s, err)
		}
	}
}
