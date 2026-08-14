package legacy

import (
	"os"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestListenerImplementsRuntime(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	doc, err := config.Parse([]byte(testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`)))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(Options{
		Bind:     doc.Listeners.LegacyTACACS.Bind,
		Settings: doc.Listeners.LegacyTACACS,
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	if ln.ID() != runtime.IDLegacyTACACS || ln.Protocol() != domain.ProtocolTACACS {
		t.Fatalf("id=%s proto=%s", ln.ID(), ln.Protocol())
	}
	if ln.Carrier() != domain.CarrierTACACSLegacyTCP {
		t.Fatalf("carrier=%s", ln.Carrier())
	}
	if ln.Role() != domain.RoleAAA {
		t.Fatalf("role=%s", ln.Role())
	}
	st := ln.Status()
	if st.Bind == "" || st.Bind == "127.0.0.1:0" {
		t.Fatalf("bind should be the actual address: %q", st.Bind)
	}
	if !st.Required || !st.Enabled {
		t.Fatalf("status=%+v", st)
	}
	if len(st.Roles) != 1 || st.Roles[0] != domain.RoleAAA {
		t.Fatalf("roles=%v", st.Roles)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
}
