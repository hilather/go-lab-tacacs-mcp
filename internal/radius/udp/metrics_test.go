package udp

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
)

func TestUnknownClientDiscardUsesClosedLabels(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "192.0.2.0/24", "127.0.0.1:0"))
	reg := observability.NewRegistry()
	rec := observability.NewRecorder(reg)
	ln, _, _ := startRole(t, doc, domain.RoleAccess, nil, rec)
	c := dialUDP(t, ln.Addr().String())
	req := accessRequest(t, 1, [16]byte{9})
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if got := readUDP(t, c, 150*time.Millisecond); got != nil {
		t.Fatalf("unknown client must be silent, got %d bytes", len(got))
	}
	deadline := time.Now().Add(2 * time.Second)
	var text string
	for time.Now().Before(deadline) {
		var buf bytes.Buffer
		if err := reg.WritePrometheus(&buf); err != nil {
			t.Fatal(err)
		}
		text = buf.String()
		if strings.Contains(text, `reason_code="discard_unknown_client"`) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(text, `taclab_protocol_discards_total{protocol="radius",reason_code="discard_unknown_client",role="access",transport="udp"}`) {
		t.Fatalf("missing closed discard series:\n%s", text)
	}
	for _, leak := range []string{"client_id", "192.0.2", "loop", "User-Name", "username"} {
		if strings.Contains(text, leak) {
			t.Fatalf("forbidden label leaked %q:\n%s", leak, text)
		}
	}
}
